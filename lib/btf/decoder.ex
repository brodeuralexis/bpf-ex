defmodule BTF.Decoder do
  import BTF.Utilities

  defstruct [:btf, :path]

  @type t :: %__MODULE__{btf: BTF.t(), path: [any]}

  @spec new(BTF.t()) :: t
  def new(btf) do
    %__MODULE__{btf: btf, path: []}
  end

  @spec decode(t(), BTF.type(), any) :: {:ok, binary} | {:error, any}
  def decode(%__MODULE__{} = decoder, type, value) do
    case do_decode(decoder, type, value) do
      {:ok, value, <<>>} ->
        {:ok, value}

      {:ok, _value, rest} ->
        {:error,
         %BTF.Error{
           message: """
           Failed to decode value, as there is a leftover of #{bit_size(rest)} bits.
           """
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec do_decode(t, BTF.type(), binary) :: {:ok, any, binary} | {:error, any}
  defp do_decode(decoder, %{kind: kind} = type, value) do
    case kind do
      :int -> decode_int(decoder, type, value)
      :ptr -> decode_ptr(decoder, type, value)
      :array -> decode_array(decoder, type, value)
      :struct -> decode_struct(decoder, type, value)
      :union -> decode_union(decoder, type, value)
      :enum -> decode_enum(decoder, type, value)
      :fwd -> decode_fwd(decoder, type, value)
      :typedef -> decode_typedef(decoder, type, value)
      :volatile -> decode_volatile(decoder, type, value)
      :const -> decode_const(decoder, type, value)
      :restrict -> decode_restrict(decoder, type, value)
      :func -> decode_func(decoder, type, value)
      :func_proto -> decode_func_proto(decoder, type, value)
      :var -> decode_var(decoder, type, value)
      :datasec -> decode_datasec(decoder, type, value)
      :float -> decode_float(decoder, type, value)
      :decl_tag -> decode_decl_tag(decoder, type, value)
      :type_tag -> decode_type_tag(decoder, type, value)
      :enum64 -> decode_enum64(decoder, type, value)
    end
  end

  @spec decode_int(t, BTF.int_type(), binary) :: {:ok, integer, binary} | {:error, any}
  defp decode_int(decoder, type, value) do
    bits = type.bits
    signed = type.encoding.signed
    endianness = decoder.btf.endianness

    int_descriptor = {endianness, signed, bits}

    do_decode_int(decoder, int_descriptor, value)
  end

  @spec do_decode_int(t, {BTF.endianness(), boolean, non_neg_integer}, binary) ::
          {:ok, integer, binary} | {:error, any}
  defp do_decode_int(decoder, {:little, true, bits}, data) do
    case data do
      <<value::little-signed-integer-size(bits)-unit(1), rest::binary>> ->
        {:ok, value, rest}

      data ->
        fail_decode_int(decoder, data)
    end
  end

  defp do_decode_int(decoder, {:little, false, bits}, data) do
    case data do
      <<value::little-unsigned-integer-size(bits)-unit(1), rest::binary>> ->
        {:ok, value, rest}

      data ->
        fail_decode_int(decoder, data)
    end
  end

  defp do_decode_int(decoder, {:big, true, bits}, data) do
    case data do
      <<value::big-signed-integer-size(bits)-unit(1), rest::binary>> ->
        {:ok, value, rest}

      data ->
        fail_decode_int(decoder, data)
    end
  end

  defp do_decode_int(decoder, {:big, false, bits}, data) do
    case data do
      <<value::big-unsigned-integer-size(bits)-unit(1), rest::binary>> ->
        {:ok, value, rest}

      data ->
        fail_decode_int(decoder, data)
    end
  end

  @spec fail_decode_int(t, binary) :: {:error, any}
  defp fail_decode_int(decoder, data) do
    {:error,
     %BTF.Error{
       message: """
       Failed to decode an integer at #{inspect(path(decoder))}.

       Impossible to decode #{inspect(data)} into an integer.
       """
     }}
  end

  @spec decode_ptr(t, BTF.ptr_type(), binary) :: {:error, any}
  defp decode_ptr(decoder, _type, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode pointers at #{inspect(path(decoder))}.

       When encoding and decoding from BTF, pointers have no valid meaning, as it would be impossible for userspace to know about kernel memory and vice-versa.
       """
     }}
  end

  @spec decode_array(t, BTF.array_type(), binary) :: {:ok, [any], binary} | {:error, any}
  defp decode_array(decoder, %{type: elem_type_id, nelems: n}, value) do
    with {:ok, elem_type} <- find_type(decoder, elem_type_id),
         {:ok, elements, rest} <- do_decode_array(decoder, elem_type, n, 0, value, []) do
      {:ok, Enum.reverse(elements), rest}
    end
  end

  @spec do_decode_array(t, BTF.type(), non_neg_integer, non_neg_integer, binary, [any]) ::
          {:ok, [any], binary} | {:error, any}
  defp do_decode_array(_decoder, _elem_type, n, n, rest, elements) do
    {:ok, elements, rest}
  end

  defp do_decode_array(decoder, elem_type, n, i, data, acc) do
    with {:ok, element, rest} <- do_decode(push_path(decoder, i), elem_type, data) do
      do_decode_array(decoder, elem_type, n, i + 1, rest, [element | acc])
    end
  end

  @spec decode_struct(t, BTF.struct_type(), binary) :: {:ok, map, binary} | {:error, any}
  defp decode_struct(decoder, %{members: members, size: size}, value) do
    with {:ok, struct, rest} <- do_decode_struct(decoder, {members, bit_size(value)}, %{}, value) do
      diff = bit_size(value) - bit_size(rest)

      cond do
        diff == size * 8 ->
          {:ok, struct, rest}

        diff < size * 8 ->
          case rest do
            <<_padding::size(diff - size)-unit(1), rest::binary>> ->
              {:ok, struct, rest}

            _ ->
              {:error,
               %BTF.Error{
                 message: """
                 Failed to decode a struct at #{inspect(path(decoder))}.

                 There was some missing padding of #{diff - size} bits when attempting to decode the end of a struct.
                 """
               }}
          end
      end
    end
  end

  @spec do_decode_struct(t, {[BTF.struct_or_union_member()], non_neg_integer}, map, binary) ::
          {:ok, map, binary} | {:error, any}
  defp do_decode_struct(_decoder, {[], _start}, struct, rest) do
    {:ok, struct, rest}
  end

  defp do_decode_struct(
         decoder,
         {[%{type: member_type_id, name: member_name, offset: member_offset} | members], start},
         struct,
         data
       ) do
    with {:ok, data} <- unpad_struct_member(decoder, start, member_offset, data),
         {:ok, member_type} <- find_type(decoder, member_type_id),
         {:ok, member_value, data} <-
           do_decode(push_path(decoder, member_name), member_type, data) do
      struct = Map.put_new(struct, member_name, member_value)
      do_decode_struct(decoder, {members, start}, struct, data)
    end
  end

  defp do_decode_struct(
         decoder,
         {[%{type: member_type_id, offset: member_offset} | members], start},
         struct,
         data
       ) do
    with {:ok, data} <- unpad_struct_member(decoder, start, member_offset, data),
         {:ok, member_type} <- find_type(decoder, member_type_id) do
      if member_type.kind == :struct do
        with {:ok, inner_struct, rest} <- decode_struct(decoder, member_type, data) do
          struct = Map.merge(struct, inner_struct)
          do_decode_struct(decoder, {members, start}, struct, rest)
        end
      else
        with {:ok, bits} <- bit_size(decoder.btf, member_type) do
          case data do
            <<_::size(bits)-unit(1), rest::binary>> ->
              do_decode_struct(decoder, {members, start}, struct, rest)

            _ ->
              {:error,
               %BTF.Error{
                 message: """
                 Failed to decode a struct at #{inspect(path(decoder))}.

                 Reached an end of input before the struct could be successfully decoded.
                 """
               }}
          end
        end
      end
    end
  end

  @spec unpad_struct_member(t, non_neg_integer, non_neg_integer, binary) ::
          {:ok, binary} | {:error, any}
  defp unpad_struct_member(decoder, start, member_offset, acc) do
    actual_offset = start - bit_size(acc)
    expected_offset = member_offset

    cond do
      expected_offset == actual_offset ->
        {:ok, acc}

      expected_offset > actual_offset ->
        case acc do
          <<_padding::size(expected_offset - actual_offset)-unit(1), acc::binary>> ->
            {:ok, acc}

          _ ->
            {:error,
             %BTF.Error{
               message: """
               Failed to decode a struct at #{inspect(path(decoder))}.

               Attempted to decode a member that has some padding due to its previous member, but not enought data was available.
               """
             }}
        end
    end
  end

  @spec decode_union(t, BTF.union_type(), binary) :: {:error, any}
  defp decode_union(decoder, _type, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode unions at #{inspect(path(decoder))}.

       Decoding of unions using BTF is still an undecided functionnality, as dealing with unnamed union members makes encoding difficult.
       """
     }}
  end

  @spec decode_enum(t, BTF.enum_type(), binary) ::
          {:ok, integer | String.t(), binary} | {:error, any}
  defp decode_enum(decoder, %{enum: members, kflag: kflag, size: size}, value) do
    endianness = decoder.btf.endianness
    int_descriptor = {endianness, kflag == 1, size * 8}

    with {:ok, int, rest} <- do_decode_int(decoder, int_descriptor, value) do
      member =
        Enum.find(members, fn
          %{val: ^int} -> true
          _ -> false
        end)

      case member do
        nil ->
          {:ok, int, rest}

        %{name: name} ->
          {:ok, name, rest}
      end
    end
  end

  @spec decode_fwd(t, BTF.fwd_type(), binary) :: {:error, any}
  defp decode_fwd(decoder, %{name: name}, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode a forward declaration for type #{inspect(name)} at #{inspect(path(decoder))}.

       Forward declarations have no meaning during decoding, as they do not have a known size and definition.
       """
     }}
  end

  @spec decode_typedef(t, BTF.typedef_type(), binary) :: {:ok, any} | {:error, any}
  defp decode_typedef(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_volatile(t, BTF.volatile_type(), binary) :: {:ok, any} | {:error, any}
  defp decode_volatile(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_const(t, BTF.const_type(), binary) :: {:ok, any} | {:error, any}
  defp decode_const(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_restrict(t, BTF.restrict_type(), binary) :: {:ok, any} | {:error, any}
  defp decode_restrict(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_func(t, BTF.func_type(), binary) :: {:error, any}
  defp decode_func(decoder, _type, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode a subprogram at #{inspect(path(decoder))}.

       Decoding a subprogram is impossible.
       """
     }}
  end

  @spec decode_func_proto(t, BTF.func_proto_type(), binary) :: {:error, any}
  defp decode_func_proto(decoder, _type, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode a function prototype at #{inspect(path(decoder))}.

       What are you doing decoding a function prototype?!
       """
     }}
  end

  @spec decode_var(t, BTF.var_type(), binary) :: {:ok, any} | {:error, any}
  defp decode_var(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_datasec(t, BTF.datasec_type(), binary) :: {:error, any}
  defp decode_datasec(decoder, _type, _value) do
    {:error,
     %BTF.Error{
       message: """
       Unable to decode a datasec at #{inspect(path(decoder))}.

       A datasec is not data, but a section in an ELF object file.
       """
     }}
  end

  @spec decode_float(t, BTF.float_type(), binary) :: {:ok, float, binary} | {:error, any}
  defp decode_float(decoder, %{size: size}, value) do
    endianness = decoder.btf.endianness

    do_decode_float(decoder, {endianness, size}, value)
  end

  @spec do_decode_float(t, {BTF.endianness(), non_neg_integer()}, binary) ::
          {:ok, float, binary} | {:error, any}
  defp do_decode_float(decoder, {:little, size}, data) do
    case data do
      <<float::little-float-size(size)-unit(8), rest::binary>> ->
        {:ok, float, rest}

      _ ->
        {:error,
         %BTF.Error{
           message: """
           Failed to decode a float at #{inspect(path(decoder))}.

           Reached end of data before a float could be decoder.
           """
         }}
    end
  end

  @spec decode_decl_tag(t, BTF.decl_tag_type(), binary) :: {:ok, any, binary} | {:error, any}
  defp decode_decl_tag(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_type_tag(t, BTF.type_tag_type(), binary) :: {:ok, any, binary} | {:error, any}
  defp decode_type_tag(decoder, %{type: type_id}, value) do
    with {:ok, type} <- find_type(decoder, type_id) do
      do_decode(decoder, type, value)
    end
  end

  @spec decode_enum64(t, BTF.enum64_type(), binary) ::
          {:ok, integer | String.t(), binary} | {:error, any}
  defp decode_enum64(decoder, %{enum64: members, kflag: kflag, size: size}, value) do
    endianness = decoder.btf.endianness
    int_descriptor = {endianness, kflag == 1, size * 8}

    with {:ok, int, rest} <- do_decode_int(decoder, int_descriptor, value) do
      member =
        Enum.find(members, fn
          %{val: ^int} -> true
          _ -> false
        end)

      case member do
        nil ->
          {:ok, int, rest}

        %{name: name} ->
          {:ok, name, rest}
      end
    end
  end

  @spec push_path(t, any) :: t
  defp push_path(decoder, segment) do
    Map.update!(decoder, :path, &List.insert_at(&1, 0, segment))
  end

  @spec path(t) :: [any]
  def path(decoder) do
    Enum.reverse(decoder.path)
  end
end
