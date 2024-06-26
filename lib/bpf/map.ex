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

  @typedoc """
  The type of the `Map`.

  This is the union of all possible atoms that are currently supported by the
  library, as new map types need to be explicitly added for support.
  """
  @type type ::
          :unspec
          | :hash
          | :array
          | :prog_array
          | :perf_event_array
          | :percpu_hash
          | :percpu_array
          | :stack_trace
          | :cgroup_array
          | :lru_hash
          | :lru_percpu_hash
          | :lpm_trie
          | :array_of_maps
          | :hash_of_maps
          | :devmap
          | :sockmap
          | :cpumap
          | :xskmap
          | :sockhash
          | :cgroup_storage_deprecated
          | :reuseport_sockarray
          | :percpu_cgroup_storage
          | :queue
          | :stack
          | :sk_storage
          | :devmap_hash
          | :struct_ops
          | :ringbuf
          | :inode_storage
          | :task_storage
          | :bloom_filter
          | :user_ringbuf
          | :cgrp_storage

  @doc """
  Returns the type of the map.
  """
  @spec type(t) :: type
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
         {:ok, value} <- lookup_elem(map, key),
         {:ok, value} <- BTF.decode(btf, value_type, value) do
      {:ok, value}
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
