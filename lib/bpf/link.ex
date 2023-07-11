defmodule Bpf.Link do
  @moduledoc """
  """

  @derive {Inspect, only: []}
  defstruct [:ref]

  @type t :: %__MODULE__{
          ref: reference()
        }
end
