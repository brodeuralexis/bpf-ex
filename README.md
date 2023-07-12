# BPF

A high-level BPF library for Elixir.

`BPF` offers a high-level interface for dealing with BPF objects, programs,
maps, etc. we developping Elixir applications with a need for kernel
introspection. The library is a NIF wrapper around most of *libbpf*'s features.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `bpf` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:bpf,  git: "https://github.com/brodeuralexis/bpf-ex", branch: "master"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/bpf>.

## Usage

`BPF`, like *libbpf*, offers a high-level interface for dealing with BPF, where
the root aggregate is an *Object*. `BPF` allows to open and load objects, and
manipulate its maps and programs:

```elixir
iex(1)> object = BPF.Object.open_file!("examples/syscall_counter.o")
iex(2)> BPF.Object.load!(object)
iex(5)> link = BPF.Program.attach!(object.programs["do_sys_exit"])
iex(6)> :timer.sleep(500)
iex(7)> BPF.Map.lookup_elem(object.maps["syscall_counts"], 0)
%{"failure_counts" => 567, "success_counts" => 1822}
```
