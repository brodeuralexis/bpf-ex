defmodule BPF.Object do
  @moduledoc """
  """

  @derive {Inspect, only: [:name, :maps, :programs]}
  defstruct [:name, :maps, :programs, :btf, :ref]

  @type t :: %__MODULE__{
          name: String.t(),
          maps: %{String.t() => BPF.Map.t()},
          programs: %{String.t() => BPF.Program.t()},
          btf: BPF.BTF.t(),
          ref: reference()
        }

  @typedoc """
  Explicitly specifies the name of the object file.

  For file-based object files, this will replace the name of the file.

  For memory-based object files, this will replace the standard `<addr>-<size>`
  name.
  """
  @type object_name :: {:object_name, String.t()}

  @typedoc """
  When reading map definitions from the object file, ignore extraneous
  attributes as if they were not present.
  """
  @type relaxed_maps :: {:relaxed_maps, boolean}

  @typedoc """
  If provided, maps that have their `pinning` attribute set will be pinned to
  files in this directory.  Defaults to `"/sys/fs/bpf"`.
  """
  @type pin_root_path :: {:pin_root_path, String.t()}

  @typedoc """
  Additional kernel configuration to augment and override the host system's
  configuration for `CONFIG_xxx` externs.
  """
  @type kconfig :: {:kconfig, String.t()}

  @typedoc """
  Path to a file containing custom *BTF* information for CO-RE.
  """
  @type btf_custom_path :: {:btf_custom_path, String.t()}

  @typedoc """
  The keyword list of options that can be provided to the `open_file/1` and
  `open_file/2` function.
  """
  @type open_file_opts :: [object_name | relaxed_maps | pin_root_path | kconfig | btf_custom_path]

  @doc """
  Creates a `BPF.Object` by opening the ELF file at the provided path and
  loading it in memory.
  """
  @spec open_file(String.t()) :: {:ok, t} | {:error, any}
  @spec open_file(String.t(), open_file_opts) :: {:ok, t} | {:error, any}
  def open_file(path, opts \\ []) do
    with {:ok, ref} <- :bpf_sys.object_open_file(path, opts) do
      name = :bpf_sys.object_name(ref)
      btf = open_btf(ref)
      maps = open_maps(ref, btf)
      programs = open_programs(ref)

      {:ok,
       %__MODULE__{
         name: name,
         maps: maps,
         programs: programs,
         btf: btf,
         ref: ref
       }}
    else
      {:error, errno} ->
        {:error, BPF.Error.exception(op: :object_open, path: path, errno: errno)}
    end
  end

  @doc """
  Creates a `BPF.Object` by opening the ELF file at the provided path and
  loading it in memory.
  """
  @spec open_file!(String.t()) :: t
  @spec open_file!(String.t(), open_file_opts) :: t
  def open_file!(path, opts \\ []) do
    case open_file(path, opts) do
      {:ok, object} ->
        object

      {:error, reason} ->
        raise reason
    end
  end

  defp open_btf(ref) do
    ref = :bpf_sys.object_btf(ref)

    %BTF{
      endianness: :bpf_sys.btf_endianness(ref),
      ref: ref
    }
  end

  defp open_maps(ref, btf) do
    for ref <- :bpf_sys.object_maps(ref), into: %{} do
      name = :bpf_sys.map_name(ref)

      {name,
       %BPF.Map{
         name: name,
         btf: btf,
         ref: ref
       }}
    end
  end

  defp open_programs(ref) do
    for ref <- :bpf_sys.object_programs(ref), into: %{} do
      name = :bpf_sys.program_name(ref)
      section_name = :bpf_sys.program_section_name(ref)

      {name,
       %BPF.Program{
         name: name,
         section_name: section_name,
         ref: ref
       }}
    end
  end

  @doc """
  Loads a `BPF.Object` into the host kernel.
  """
  @spec load(t) :: :ok | {:error, any}
  def load(%__MODULE__{} = object) do
    case :bpf_sys.object_load(object.ref) do
      :ok ->
        :ok

      {:error, {errno, log}} ->
        {:error, BPF.Error.exception(op: :object_load, errno: errno, log: log)}
    end
  end

  @doc """
  Loads a `BPF.Object` into the host kernel.
  """
  @spec load!(t) :: :ok
  def load!(%__MODULE__{} = object) do
    case load(object) do
      :ok ->
        :ok

      {:error, reason} ->
        raise reason
    end
  end
end
