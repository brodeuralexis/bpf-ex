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
        {:error, BPF.AttachError.exception(errno: errno)}
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
end
