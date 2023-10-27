defmodule BPF.Program do
  @moduledoc """
  """

  @derive {Inspect, only: [:name, :section_name]}
  defstruct [:name, :section_name, :ref]

  @type t :: %__MODULE__{
          name: String.t(),
          section_name: String.t(),
          ref: reference()
        }

  @spec attach(t) :: {:ok, BPF.Link.t()} | {:error, any}
  def attach(%__MODULE__{} = program) do
    case :bpf_sys.program_attach(program.ref) do
      {:ok, ref} ->
        {:ok, %BPF.Link{ref: ref}}

      {:error, errno} ->
        {:error, BPF.Error.exception(op: :program_attach, errno: errno)}
    end
  end

  @spec attach!(t) :: BPF.Link.t()
  def attach!(%__MODULE__{} = program) do
    case attach(program) do
      {:ok, link} ->
        link

      {:error, reason} ->
        raise reason
    end
  end

  @spec autoload?(t) :: boolean
  def autoload?(%__MODULE__{} = program) do
    :bpf_sys.program_autoload(program.ref)
  end

  @spec set_autoload(t, boolean) :: nil
  def set_autoload(%__MODULE__{} = program, autoload) when is_boolean(autoload) do
    _ = :bpf_sys.program_set_autoload(program.ref, autoload)
  end

  @spec autoattach?(t) :: boolean
  def autoattach?(%__MODULE__{} = program) do
    :bpf_sys.program_autoattach(program.ref)
  end

  @spec set_autoattach(t, boolean) :: nil
  def set_autoattach(%__MODULE__{} = program, autoattach) when is_boolean(autoattach) do
    _ = :bpf_sys.program_set_autoattach(program.ref, autoattach)
  end

  @spec insns(t) :: binary
  def insns(%__MODULE__{} = program) do
    :bpf_sys.program_insns(program.ref)
  end

  @spec set_insns(t, binary) :: nil
  def set_insns(%__MODULE__{} = program, insns) when is_binary(insns) do
    _ = :bpf_sys.program_set_insns(program.ref, insns)
  end

  @spec pin(t, String.t()) :: :ok | {:error, term}
  def pin(%__MODULE__{} = program, path) when is_binary(path) do
    case :bpf_sys.program_pin(program.ref, path) do
      :ok ->
        :ok

      {:error, errno} ->
        {:error, BPF.Error.exception(op: :program_pin, path: path, errno: errno)}
    end
  end

  @spec pin!(t, String.t()) :: nil
  def pin!(%__MODULE__{} = program, path) when is_binary(path) do
    case pin(program, path) do
      :ok ->
        nil

      {:error, reason} ->
        raise reason
    end
  end

  @spec unpin(t, String.t()) :: :ok | {:error, term}
  def unpin(%__MODULE__{} = program, path) when is_binary(path) do
    case :bpf_sys.program_unpin(program.ref, path) do
      :ok ->
        :ok

      {:error, errno} ->
        {:error, BPF.Error.exception(op: :program_unpin, path: path, errno: errno)}
    end
  end

  @spec unpin!(t, String.t()) :: nil
  def unpin!(%__MODULE__{} = program, path) do
    case unpin(program, path) do
      :ok ->
        nil

      {:error, reason} ->
        raise reason
    end
  end

  @spec unload(t) :: :ok
  def unload(%__MODULE__{} = program) do
    :bpf_sys.program_unload(program.ref)
  end
end
