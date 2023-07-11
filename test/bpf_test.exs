defmodule BPFTest do
  use ExUnit.Case
  doctest BPF

  test "greets the world" do
    assert BPF.hello() == :world
  end
end
