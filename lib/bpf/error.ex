defmodule BPF.Error do
  defexception [:message, :operation, :errno]

  def exception(op: op = :map_lookup_elem, errno: errno) do
    message = "Failed to lookup map element: #{errno}"

    %BPF.Error{message: message, operation: op, errno: errno}
  end

  def exception(op: op = :map_update_elem, errno: errno) do
    message = "Failed to update map element: #{errno}"

    %BPF.Error{message: message, operation: op, errno: errno}
  end

  def exception(op: op = :object_open, errno: errno, path: path) do
    message =
      "failed to open BPF object at #{inspect(path)}, libbpf returned an #{errno} error code"

    %BPF.Error{message: message, operation: op, errno: errno}
  end

  def exception(op: op = :object_open, errno: errno) do
    message = "failed to open an in-memory BPF object, libbpf returned an #{errno} error code"

    %BPF.Error{message: message, operation: op, errno: errno}
  end

  def exception(op: op = :object_load, errno: errno, log: log) do
    message = "failed to load BPF object, libbpf returned an #{errno} error code: \n#{log}"

    %BPF.Error{message: message, operation: op, errno: errno}
  end

  def exception(op: op = :program_attach, errno: errno) do
    message = "failed to attach BPF program, libbpf returned an #{errno} error code."

    %BPF.Error{message: message, operation: op, errno: errno}
  end
end
