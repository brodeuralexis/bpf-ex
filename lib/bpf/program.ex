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
end
