defmodule :bpf_sys do
  @moduledoc false

  @on_load {:init, 0}

  defp init do
    priv_dir = :code.priv_dir(:bpf)
    nif_path = :filename.join(priv_dir, :bpf_sys)
    :erlang.load_nif(nif_path, 0)
  end

  def major_version(), do: nif_error()
  def minor_version(), do: nif_error()
  def num_possible_cpus(), do: nif_error()

  def map_name(_), do: nif_error()
  def map_type(_), do: nif_error()
  def map_lookup_elem(_, _), do: nif_error()
  def map_update_elem(_, _, _, _), do: nif_error()
  def map_btf_key_type_id(_), do: nif_error()
  def map_btf_value_type_id(_), do: nif_error()

  def object_open_file(_, _), do: nif_error()
  def object_load(_), do: nif_error()
  def object_pin_maps(_, _), do: nif_error()
  def object_unpin_maps(_, _), do: nif_error()
  def object_pin_programs(_, _), do: nif_error()
  def object_unpin_programs(_, _), do: nif_error()
  def object_name(_), do: nif_error()
  def object_kversion(_), do: nif_error()
  def object_set_kversion(_, _), do: nif_error()
  def object_btf(_), do: nif_error()
  def object_maps(_), do: nif_error()
  def object_programs(_), do: nif_error()

  def program_set_ifindex(_, _), do: nif_error()
  def program_name(_), do: nif_error()
  def program_section_name(_), do: nif_error()
  def program_autoload(_), do: nif_error()
  def program_set_autoload(_, _), do: nif_error()
  def program_autoattach(_), do: nif_error()
  def program_set_autoattach(_, _), do: nif_error()
  def program_insns(_), do: nif_error()
  def program_set_insns(_, _), do: nif_error()
  def program_pin(_, _), do: nif_error()
  def program_unpin(_, _), do: nif_error()
  def program_unload(_), do: nif_error()
  def program_attach(_), do: nif_error()
  @spec program_attach_xdp(reference(), pos_integer()) :: {:ok, reference()} | {:error, atom}
  def program_attach_xdp(_, _), do: nif_error()

  def btf_find_by_name(_, _), do: nif_error()
  def btf_find_by_id(_, _), do: nif_error()
  def btf_endianness(_), do: nif_error()

  @spec link_open(String.t()) :: {:ok, reference()} | {:error, atom}
  def link_open(_), do: nif_error()
  @spec link_disconnect(reference()) :: :ok
  def link_disconnect(_), do: nif_error()
  @spec link_detach(reference()) :: :ok
  def link_detach(_), do: nif_error()
  @spec link_pin_path(reference()) :: String.t() | nil
  def link_pin_path(_), do: nif_error()
  @spec link_pin(reference(), String.t()) :: :ok | {:error, atom}
  def link_pin(_, _), do: nif_error()
  @spec link_unpin(reference()) :: :ok | {:error, atom}
  def link_unpin(_), do: nif_error()

  defp nif_error do
    :erlang.nif_error(:bpf_sys)
  end
end
