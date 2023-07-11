defmodule BTF.Encoder do
  @moduledoc false

  import BTF.Utilities

  defstruct [:btf, :path]

  @type t :: %__MODULE__{btf: BTF.t(), path: [any]}

  def new(%BTF{} = btf) do
    %__MODULE__{btf: btf, path: []}
  end

  @spec encode(t, BTF.type(), any) :: {:ok, binary} | {:error, any}
  def encode(%__MODULE__{} = encoder, type, value) do
    do_encode(encoder, type, value, <<>>)
  end

  @spec do_encode(t, BTF.type(), any, binary) :: {:ok, binary} | {:error, any}
  defp do_encode(encoder, %{kind: kind} = type, value, acc) do
    case kind do
      :int -> encode_int(encoder, type, value, acc)
      :ptr -> encode_ptr(encoder, type, value, acc)
      :array -> encode_array(encoder, type, value, acc)
      :struct -> encode_struct(encoder, type, value, acc)
      :union -> encode_union(encoder, type, value, acc)
      :enum -> encode_enum(encoder, type, value, acc)
      :fwd -> encode_fwd(encoder, type, value, acc)
      :typedef -> encode_typedef(encoder, type, value, acc)
      :volatile -> encode_volatile(encoder, type, value, acc)
      :const -> encode_const(encoder, type, value, acc)
      :restrict -> encode_restrict(encoder, type, value, acc)
      :func -> encode_func(encoder, type, value, acc)
      :func_proto -> encode_func_proto(encoder, type, value, acc)
      :var -> encode_var(encoder, type, value, acc)
      :datasec -> encode_datasec(encoder, type, value, acc)
      :float -> encode_float(encoder, type, value, acc)
      :decl_tag -> encode_decl_tag(encoder, type, value, acc)
      :type_tag -> encode_type_tag(encoder, type, value, acc)
      :enum64 -> encode_enum64(encoder, type, value, acc)
    end
  end

  @spec encode_int(t, BTF.int_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_int(encoder, type, true, acc) do
    encode_int(encoder, type, 1, acc)
  end

  defp encode_int(encoder, type, false, acc) do
    encode_int(encoder, type, 0, acc)
  end

  defp encode_int(encoder, type, value, acc) when is_integer(value) do
    bits = type.bits
    signed = type.encoding.signed
    endianness = encoder.btf.endianness

    int_descriptor = {endianness, signed, bits}

    with :ok <- prevent_overflow(encoder, int_descriptor, value) do
      do_encode_int(encoder, int_descriptor, value, acc)
    end
  end

  defp encode_int(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode a integer at #{inspect(path(encoder))}.

       Expected an integer, but got a #{typeof(value)} instead.
       """
     }}
  end

  @spec prevent_overflow(t, {:little | :bit, boolean, non_neg_integer}, integer) ::
          :ok | {:error, any}
  defp prevent_overflow(encoder, {_endianness, signed, bits}, value) when is_integer(value) do
    # Check for overflow or underflow of integer types.
    {min_limit, max_limit} =
      if signed do
        limit = Integer.pow(2, bits - 1)
        {-limit, limit}
      else
        {0, Integer.pow(2, bits)}
      end

    cond do
      value < min_limit ->
        {:error,
         %BTF.Error{
           message: """
           Failed to encode an integer due to an underflow at #{inspect(path(encoder))}.

           The minimum expected integer value of #{min_limit} was exceeded by the actual value of #{value}.
           """
         }}

      value >= max_limit ->
        {:error,
         %BTF.Error{
           message: """
           Failed to encode an integer due to an overflow at #{inspect(path(encoder))}.

           The maximum expected integer value of #{max_limit} was exceeded by the actual value of #{value}.
           """
         }}

      true ->
        :ok
    end
  end

  @spec do_encode_int(t, {BTF.endianness(), boolean, non_neg_integer}, integer, binary) ::
          {:ok, binary} | {:error, any}
  defp do_encode_int(_encoder, {:little, true, bits}, value, acc) do
    {:ok, <<acc::binary, value::signed-little-integer-size(bits)-unit(1)>>}
  end

  defp do_encode_int(_encoder, {:little, false, bits}, value, acc) do
    {:ok, <<acc::binary, value::unsigned-little-integer-size(bits)-unit(1)>>}
  end

  defp do_encode_int(_encoder, {:big, true, bits}, value, acc) do
    {:ok, <<acc::binary, value::signed-big-integer-size(bits)-unit(1)>>}
  end

  defp do_encode_int(_encoder, {:big, false, bits}, value, acc) do
    {:ok, <<acc::binary, value::unsigned-big-integer-size(bits)-unit(1)>>}
  end

  @spec encode_ptr(t, BTF.ptr_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_ptr(encoder, _type, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode pointers at #{inspect(path(encoder))}.

       When encoding and decoding from BTF, pointers have no valid meaning, as it would be impossible for userspace to know about kernel memory and vice-versa.
       """
     }}
  end

  @spec encode_array(t, BTF.array_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_array(encoder, %{type: elem_type_id, nelems: n}, value, acc) when is_list(value) do
    with {:ok, elem_type} <- find_type(encoder, elem_type_id) do
      do_encode_array(encoder, elem_type, n, 0, value, acc)
    end
  end

  defp encode_array(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode an array at #{inspect(path(encoder))}.

       The BTF type is an array, but the type received is a #{typeof(value)}.
       """
     }}
  end

  @spec do_encode_array(t, BTF.type(), non_neg_integer, non_neg_integer, list, binary) ::
          {:ok, binary} | {:error, any}
  defp do_encode_array(_encoder, _elem_type, n, n, [], acc) do
    {:ok, acc}
  end

  defp do_encode_array(encoder, _elem_type, n, i, [], _acc) do
    # NOTE: Allow this condition by zeroing elements?
    {:error,
     %BTF.Error{
       message: """
       Failed to encode an array at #{inspect(path(encoder))}.

       The BTF array has #{n} elements, but the provided list only has #{i} elements.
       """
     }}
  end

  defp do_encode_array(encoder, _elem_type, n, n, value, _acc) do
    # NOTE: Allow this condition by ignoring the rest?
    {:error,
     %BTF.Error{
       message: """
       Failed to encode an array at #{inspect(path(encoder))}.

       The BTF array has #{n} elements, but the provided list has #{n + length(value)} elements.
       """
     }}
  end

  defp do_encode_array(encoder, elem_type, n, i, [value | rest], acc) do
    with {:ok, acc} <- do_encode(encoder, elem_type, value, acc) do
      do_encode_array(encoder, elem_type, n, i + 1, rest, acc)
    end
  end

  @spec encode_struct(t, BTF.struct_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_struct(encoder, %{members: members, size: size}, value, acc) when is_map(value) do
    do_encode_struct(encoder, {size, members, bit_size(acc)}, value, acc)
  end

  defp encode_struct(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode a struct at #{inspect(path(encoder))}.

       The BTF type is a struct, but the received type is a #{typeof(value)}.
       """
     }}
  end

  @spec do_encode_struct(
          t,
          {non_neg_integer, [BTF.struct_or_union_member()], non_neg_integer},
          any,
          binary
        ) :: {:ok, binary} | {:error, any}
  defp do_encode_struct(_encoder, {size, [], _start}, _value, acc) do
    diff = bit_size(acc) - size * 8

    # We have finished iterating over the members, but there might be some additionnal padding at the end of the data
    # structure.
    if diff == 0 do
      {:ok, acc}
    else
      {:ok, <<acc::binary, 0::size(diff)-unit(1)>>}
    end
  end

  defp do_encode_struct(
         encoder,
         {size, [%{type: member_type_id, name: member_name, offset: member_offset} | members],
          start},
         value,
         acc
       ) do
    acc = pad_struct_member(start, member_offset, acc)

    with {:ok, member_type} <- find_type(encoder, member_type_id) do
      case Map.fetch(value, member_name) do
        {:ok, member_value} ->
          with {:ok, acc} <-
                 do_encode(push_path(encoder, member_name), member_type, member_value, acc) do
            do_encode_struct(encoder, {size, members, start}, value, acc)
          end

        :error ->
          with {:ok, zero} <- zeroed(encoder.btf, member_type) do
            do_encode_struct(
              encoder,
              {size, members, start},
              value,
              <<acc::binary, zero::binary>>
            )
          end
      end
    end
  end

  defp do_encode_struct(
         encoder,
         {size, [%{type: member_type_id, offset: member_offset} | members], start},
         value,
         acc
       ) do
    acc = pad_struct_member(start, member_offset, acc)

    with {:ok, member_type} <- find_type(encoder, member_type_id),
         {:ok, zero} <- zeroed(encoder.btf, member_type) do
      do_encode_struct(encoder, {size, members, start}, value, <<acc::binary, zero::binary>>)
    end
  end

  @spec pad_struct_member(non_neg_integer, non_neg_integer, binary) :: binary
  defp pad_struct_member(start, member_offset, acc) do
    expected_offset = start + member_offset
    actual_offset = bit_size(acc)

    cond do
      expected_offset == actual_offset ->
        acc

      expected_offset > actual_offset ->
        <<acc::binary, 0::size(expected_offset - actual_offset)-unit(1)>>
    end
  end

  @spec encode_union(t, BTF.union_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_union(encoder, _type, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode unions at #{inspect(path(encoder))}.

       Encoding of unions using BTF is still an undecided functionnality, as dealing with unnamed union members makes encoding difficult.
       """
     }}
  end

  @spec encode_enum(t, BTF.enum_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_enum(encoder, type, value, acc)
       when is_binary(value) or is_integer(value) do
    do_encode_enum(encoder, type, value, acc)
  end

  defp encode_enum(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode an enum at #{inspect(path(encoder))}.

       Expected an integer or binary, but got a #{typeof(value)} instead.
       """
     }}
  end

  @spec do_encode_enum(t, BTF.enum_type(), integer | String.t(), binary) ::
          {:ok, binary} | {:error, any}
  def do_encode_enum(encoder, %{size: size, kflag: kflag, enum: enum_members}, value, acc) do
    enum_member =
      Enum.find(enum_members, fn
        %{val: ^value} -> true
        %{name: ^value} -> true
        _ -> false
      end)

    case enum_member do
      nil ->
        {:error,
         %BTF.Error{
           message: """
           """
         }}

      %{val: value} ->
        do_encode_int(encoder, {encoder.btf.endianness, kflag == 1, size * 8}, value, acc)
    end
  end

  @spec encode_fwd(t, BTF.fwd_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_fwd(encoder, %{name: name}, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode a forward declaration for type #{inspect(name)} at #{inspect(path(encoder))}.

       Forward declarations have no meaning during encoding, as they do not have a known size and definition.
       """
     }}
  end

  @spec encode_typedef(t, BTF.typedef_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_typedef(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_volatile(t, BTF.volatile_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_volatile(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_const(t, BTF.const_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_const(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_restrict(t, BTF.restrict_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_restrict(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_func(t, BTF.func_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_func(encoder, _type, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode a subprogram at #{inspect(path(encoder))}.

       Encoding a subprogram is impossible.
       """
     }}
  end

  @spec encode_func_proto(t, BTF.func_proto_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_func_proto(encoder, _type, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode a function prototype at #{inspect(path(encoder))}.

       What are you doing encoding a function prototype?!
       """
     }}
  end

  @spec encode_var(t, BTF.var_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_var(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_datasec(t, BTF.datasec_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_datasec(encoder, _type, _value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Unable to encode a datasec at #{inspect(path(encoder))}.

       A datasec is not data, but a section in an ELF object file.
       """
     }}
  end

  @spec encode_float(t, BTF.float_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_float(encoder, %{size: size}, value, acc) when is_number(value) do
    endianness = encoder.btf.endianness

    do_encode_float(encoder, {endianness, size}, value, acc)
  end

  defp encode_float(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode a float at #{inspect(path(encoder))}.

       Expected a number, but got a #{typeof(value)} instead.
       """
     }}
  end

  @spec do_encode_float(t, {BTF.endianness(), non_neg_integer}, number, binary) ::
          {:ok, binary} | {:error, any}
  defp do_encode_float(_encoder, {:little, size}, value, acc) do
    {:ok, <<acc::binary, value::float-little-size(size)-unit(8)>>}
  end

  defp do_encode_float(_encoder, {:big, size}, value, acc) do
    {:ok, <<acc::binary, value::float-big-size(size)-unit(8)>>}
  end

  @spec encode_decl_tag(t, BTF.decl_tag_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_decl_tag(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_type_tag(t, BTF.type_tag_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_type_tag(encoder, %{type: type_id}, value, acc) do
    with {:ok, type} <- find_type(encoder, type_id) do
      do_encode(encoder, type, value, acc)
    end
  end

  @spec encode_enum64(t, BTF.enum64_type(), any, binary) :: {:ok, binary} | {:error, any}
  defp encode_enum64(encoder, type, value, acc) when is_integer(value) or is_binary(value) do
    do_encode_enum64(encoder, type, value, acc)
  end

  defp encode_enum64(encoder, _type, value, _acc) do
    {:error,
     %BTF.Error{
       message: """
       Failed to encode an enum64 at #{inspect(path(encoder))}.

       Expected an integer or binary, but got a #{typeof(value)} instead.
       """
     }}
  end

  @spec do_encode_enum64(t, BTF.enum64_type(), integer | String.t(), binary) ::
          {:ok, binary} | {:error, any}
  defp do_encode_enum64(encoder, %{enum64: enum_members, size: size, kflag: kflag}, value, acc) do
    enum_member =
      Enum.find(enum_members, fn
        %{val: ^value} -> true
        %{name: ^value} -> true
        _ -> false
      end)

    case enum_member do
      nil ->
        {:error,
         %BTF.Error{
           message: """
           """
         }}

      %{val: value} ->
        endianness = encoder.btf.endianness
        do_encode_int(encoder, {endianness, kflag == 1, size}, value, acc)
    end
  end

  @spec push_path(t, String.t() | integer) :: t
  defp push_path(encoder, segment) do
    Map.update!(encoder, :path, &List.insert_at(&1, 0, segment))
  end

  @spec path(t) :: [String.t() | integer]
  defp path(encoder) do
    Enum.reverse(encoder.path)
  end
end
