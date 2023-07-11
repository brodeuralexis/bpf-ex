defmodule BPF.OpenError do
  defexception [:message, :errno]

  @impl true
  def exception(opts)

  def exception(errno: errno, path: path) do
    message =
      "failed to open BPF object at #{inspect(path)}, libbpf returned an " <>
        "#{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end

  def exception(errno: errno) do
    message =
      "failed to open an in-memory BPF object, libbpf returned an " <>
        "#{errno} error code"

    %__MODULE__{message: message, errno: errno}
  end
end

defmodule BPF.LoadError do
  defexception [:message, :errno, :log]

  @impl true
  def exception(errno: errno, log: log) do
    message =
      "failed to load BPF object, libbpf returned an #{errno} " <>
        "error code: \n#{log}"

    %__MODULE__{message: message, errno: errno, log: log}
  end
end

defmodule BPF.AttachError do
  defexception [:message, :errno]

  @impl true
  def exception(errno: errno) do
    message =
      "failed to attach BPF program, libbpf returned an #{errno} error " <>
        "code."

    %__MODULE__{message: message, errno: errno}
  end
end
