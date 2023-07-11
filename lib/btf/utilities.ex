defmodule BTF.Utilities do
  @moduledoc false

  @ptr_bits 64
  @bytes_per_bit 8

  @spec zeroed(BTF.t(), BTF.type()) :: {:ok, binary} | {:error, any}
  def zeroed(%BTF{} = btf, type) do
    with {:ok, bits} <- bit_size(btf, type) do
      {:ok, <<0::size(bits)>>}
    end
  end

  @spec bit_size(BTF.t(), BTF.type()) :: {:ok, non_neg_integer} | {:error, any}
  def bit_size(btf, type)

  def bit_size(%BTF{}, %{kind: :int, bits: bits}) do
    {:ok, bits}
  end

  def bit_size(%BTF{}, %{kind: :ptr}) do
    {:ok, @ptr_bits}
  end

  def bit_size(%BTF{} = btf, %{kind: :array, type: elem_type_id, nelems: n}) do
    with {:ok, elem_type} <- find_type(%{btf: btf}, elem_type_id),
         {:ok, elem_bit_size} <- bit_size(btf, elem_type) do
      {:ok, n * elem_bit_size}
    end
  end

  def bit_size(%BTF{}, %{kind: :struct, size: size}) do
    {:ok, size * @bytes_per_bit}
  end

  def bit_size(%BTF{}, %{kind: :union, size: size}) do
    {:ok, size * @bytes_per_bit}
  end

  def bit_size(%BTF{}, %{kind: :fwd}) do
    raise RuntimeError, """
    Cannot compute the size of a forward declaration.

    This is probably a problem with the BTF information, as programs should not compile if maps are using unsized data
    types.
    """
  end

  def bit_size(%BTF{} = btf, %{kind: :typedef, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{} = btf, %{kind: :volatile, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{} = btf, %{kind: :const, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{} = btf, %{kind: :restrict, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{}, %{kind: :func}) do
    raise RuntimeError, """
    Cannot compute the size of a subprogram.

    This is a problem with the BTF data generated while compiling the BPF programs.
    """
  end

  def bit_size(%BTF{}, %{kind: :func_proto}) do
    raise RuntimeError, """
    Cannot compute the size of a function prototype.

    This is probably a problem with the BTF information, as programs should not compile if maps are using unsized data
    types.
    """
  end

  def bit_size(%BTF{} = btf, %{kind: :var, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{}, %{kind: :datasec, size: size}) do
    {:ok, size * @bytes_per_bit}
  end

  def bit_size(%BTF{}, %{kind: :float, size: size}) do
    {:ok, size * @bytes_per_bit}
  end

  def bit_size(%BTF{} = btf, %{kind: :decl_tag, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{} = btf, %{kind: :type_tag, type: type_id}) do
    with {:ok, type} <- find_type(%{btf: btf}, type_id),
         {:ok, size} <- bit_size(btf, type) do
      {:ok, size}
    end
  end

  def bit_size(%BTF{}, %{kind: :enum64, size: size}) do
    {:ok, size * @bytes_per_bit}
  end

  @spec typeof(any) :: atom
  def typeof(value)

  def typeof(true), do: :boolean
  def typeof(false), do: :boolean
  def typeof(nil), do: nil
  def typeof(value) when is_atom(value), do: :atom
  def typeof(value) when is_map(value), do: :map
  def typeof(value) when is_pid(value), do: :pid
  def typeof(value) when is_port(value), do: :port
  def typeof(value) when is_reference(value), do: :reference
  def typeof(value) when is_tuple(value), do: :tuple
  def typeof(value) when is_float(value), do: :float
  def typeof(value) when is_integer(value), do: :integer
  def typeof(value) when is_list(value), do: :list
  def typeof(value) when is_binary(value), do: :binary
  def typeof(value) when is_function(value), do: :function

  @spec find_type(any, BTF.type_id() | BTF.type_name()) ::
          {:ok, BTF.type()} | {:error, any}
  def find_type(%{btf: btf}, type_id) when is_integer(type_id) do
    case BTF.find_by_id(btf, type_id) do
      {:ok, type} ->
        {:ok, type}

      :error ->
        {:error,
         %BTF.Error{
           message: """
           Failed to find BTF type with id #{type_id}.

           Perhaps the provided BTF data is malformatted, incomplete, etc.  This error should not happen with valid programs generated successfully by compilers like Clang or GCC.
           """
         }}
    end
  end

  def find_type(%{btf: btf}, type_name) when is_binary(type_name) do
    case BTF.find_by_name(btf, type_name) do
      {:ok, type} ->
        {:ok, type}

      :error ->
        {:error,
         %BTF.Error{
           message: """
           Failed to find BTF type with name #{inspect(type_name)}.

           Perhaps the provided BTF data is malformatted, incomplete, etc.  This error should not happen with valid programs generated successfully by compilers like Clang or GCC.
           """
         }}
    end
  end
end
