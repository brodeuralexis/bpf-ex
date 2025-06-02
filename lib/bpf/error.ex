defmodule BPF.Error do
  defexception [:message, :errno]

  @impl true
  def exception(opts)

  def exception(op: :object_open, path: path, errno: errno) do
    message =
      "failed to open BPF object at #{inspect(path)}, libbpf returned an #{errno} error code."

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :object_open, errno: errno) do
    message = "failed to open an in-memory BPF object, libbpf returned an #{errno} error code."

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :object_load, errno: errno, log: log) do
    message =
      "failed to load BPF object, libbpf returned an #{errno} error code with the following logs: #{log}"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :object_attach, errno: errno) do
    message = "failed to attach BPF program, libbpf returned an #{errno} error code."

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :program_pin, path: path, errno: errno) do
    message =
      "failed to pin BPF program using path #{inspect(path)}, libbpf returned an #{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :program_unpin, path: path, errno: errno) do
    message =
      "failed to unpin BPF program using path #{inspect(path)}, libbpf returned an #{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :program_attach, errno: errno) do
    message = "failed to attach BPF program, libbpf return an #{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :link_pin, path: path, errno: errno) do
    message =
      "failed to pin BPF link using path #{inspect(path)}, libbpf returned an #{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(op: :link_unpin, errnor: errno) do
    message = "failed to unpin BPF link, libbpf returned an #{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end
end
