defmodule BPF.Link do
  @moduledoc """
  """

  @derive {Inspect, only: []}
  defstruct [:ref]

  @type t :: %__MODULE__{
          ref: reference()
        }

  @spec open(String.t()) :: t()
  def open(path) when is_binary(path) do
    with {:ok, ref} <- :bpf_sys.link_open(path) do
      {:ok, %__MODULE__{ref: ref}}
    end
  end

  @spec disconnect(t()) :: nil
  def disconnect(%__MODULE__{ref: ref}) do
    :bpf_sys.link_disconnect(ref)
  end

  @spec detach(t()) :: nil
  def detach(%__MODULE__{ref: ref}) do
    :bpf_sys.link_detach(ref)
  end

  @spec pin_path(t()) :: String.t() | nil
  def pin_path(%__MODULE__{ref: ref}) do
    :bpf_sys.link_pin_path(ref)
  end

  @spec pin(t(), String.t()) :: :ok | {:error, term}
  def pin(%__MODULE__{ref: ref}, path) when is_binary(path) do
    :bpf_sys.link_pin(ref, path)
  end

  @spec unpin(t()) :: :ok | {:error, term}
  def unpin(%__MODULE__{ref: ref}) do
    :bpf_sys.link_unpin(ref)
  end
end
