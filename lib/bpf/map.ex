defmodule BPF.Map do
  @moduledoc """
  """

  @derive {Inspect, only: [:name]}
  defstruct [:name, :btf, :ref]

  @type t :: %__MODULE__{
          name: String.t(),
          btf: BPF.BTF.t() | nil,
          ref: reference()
        }

  def type(%__MODULE__{} = map) do
    :bpf_sys.map_type(map.ref)
  end

  def lookup_elem(%__MODULE__{btf: _} = map, key) when is_binary(key) do
    case :bpf_sys.map_lookup_elem(map.ref, key) do
      {:ok, value} ->
        {:ok, value}

      {:error, errno} ->
        {:error,
         %BPF.Error{
           message: """
           Failed to lookup map element: #{errno}.
           """
         }}
    end
  end

  def lookup_elem(%__MODULE__{btf: btf} = map, key) do
    key_type_id = :bpf_sys.map_btf_key_type_id(map.ref)
    value_type_id = :bpf_sys.map_btf_value_type_id(map.ref)

    with {:ok, key_type} <- BTF.find_by_id(btf, key_type_id),
         {:ok, value_type} <- BTF.find_by_id(btf, value_type_id),
         {:ok, key} <- BTF.encode(btf, key_type, key),
         {:ok, value} <- lookup_elem(map, key) do
      case value do
        values when is_list(values) ->
          values
          |> Stream.map(&BTF.decode(btf, value_type, &1))
          |> Enum.reduce_while({:ok, []}, fn
            {:ok, value}, {:ok, acc} ->
              {:cont, {:ok, [value | acc]}}

            {:error, reason}, {:ok, _acc} ->
              {:halt, {:error, reason}}
          end)

        value when is_binary(value) ->
          BTF.decode(btf, value_type, value)
      end
    end
  end

  def lookup_elem!(map, key) do
    case lookup_elem(map, key) do
      {:ok, value} ->
        value

      {:error, reason} ->
        raise reason
    end
  end

  def update_elem(map, key, value, opts \\ [])

  def update_elem(%__MODULE__{btf: _} = map, key, value, opts)
      when is_binary(key) and is_binary(value) do
    opts = Keyword.validate!(opts, [:exist])

    case :bpf_sys.map_update_elem(map.ref, key, value, opts) do
      :ok ->
        :ok

      {:error, errno} ->
        {:error,
         %BPF.Error{
           message: """
           Failed to update map element: #{errno}.
           """
         }}
    end
  end

  def update_elem(%__MODULE__{btf: btf} = map, key, value, opts) do
    key_type_id = :bpf_sys.map_btf_key_type_id(map.ref)
    value_type_id = :bpf_sys.map_btf_value_type_id(map.ref)

    with {:ok, key_type} <- BTF.find_by_id(btf, key_type_id),
         {:ok, value_type} <- BTF.find_by_id(btf, value_type_id),
         {:ok, key} <- BTF.encode(btf, key_type, key),
         {:ok, value} <- BTF.encode(btf, value_type, value),
         :ok <- update_elem(map, key, value, opts) do
      :ok
    end
  end

  def update_elem!(map, key, value, opts \\ []) do
    case update_elem(map, key, value, opts) do
      :ok ->
        :ok

      {:error, reason} ->
        raise reason
    end
  end
end
