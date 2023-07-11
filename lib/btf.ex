defmodule BTF do
  @moduledoc """
  """

  @derive {Inspect, only: [:endianness]}
  defstruct [:endianness, :ref]

  @type type_id :: non_neg_integer()

  @type type_name :: String.t()

  @type int_encoding :: %{signed: boolean, char: boolean, bool: boolean}

  @type int_type :: %{
          optional(:name) => String.t(),
          kind: :int,
          size: non_neg_integer,
          encoding: int_encoding,
          bits: non_neg_integer,
          offset: non_neg_integer
        }

  @type ptr_type :: %{
          optional(:name) => String.t(),
          kind: :ptr,
          type: type_id
        }

  @type array_type :: %{
          optional(:name) => String.t(),
          kind: :array,
          type: type_id,
          index_type: type_id,
          nelems: non_neg_integer
        }

  @type struct_or_union_member :: %{
          optional(:name) => String.t(),
          type: type_id,
          offset: non_neg_integer
        }

  @type struct_or_union_type(kind) ::
          %{
            optional(:name) => String.t(),
            kind: kind,
            kflag: 0 | 1,
            vlen: non_neg_integer,
            size: non_neg_integer,
            members: [struct_or_union_member]
          }

  @type struct_type :: struct_or_union_type(:struct)

  @type union_type :: struct_or_union_type(:union)

  @type enum_member :: %{
          optional(:name) => String.t(),
          val: integer
        }

  @type enum_type :: %{
          optional(:name) => String.t(),
          kind: :enum,
          kflag: 0 | 1,
          vlen: non_neg_integer,
          size: non_neg_integer,
          enum: [enum_member]
        }

  @type fwd_type :: %{
          optional(:name) => String.t(),
          kind: :fwd,
          kflag: 0 | 1
        }

  @type modifier_type(kind) :: %{
          optional(:name) => String.t(),
          kind: kind,
          type: type_id
        }

  @type typedef_type :: modifier_type(:typedef)

  @type volatile_type :: modifier_type(:volatile)

  @type const_type :: modifier_type(:const)

  @type restrict_type :: modifier_type(:restrict)

  @type func_type :: %{
          optional(:name) => String.t(),
          kind: :func,
          type: type_id,
          vlen: :static | :global | :extern
        }

  @type func_proto_param :: %{
          optional(:name) => String.t(),
          type: type_id
        }

  @type func_proto_type :: %{
          optional(:name) => String.t(),
          kind: :func_proto,
          vlen: non_neg_integer,
          type: type_id,
          params: [func_proto_param]
        }

  @type var_type :: %{
          optional(:name) => String.t(),
          kind: :var,
          type: type_id,
          linkage: :global | :static
        }

  @type datasec_info :: %{
          type: type_id,
          offset: non_neg_integer,
          size: non_neg_integer
        }

  @type datasec_type :: %{
          optional(:name) => String.t(),
          kind: :datasec,
          vlen: non_neg_integer,
          size: non_neg_integer,
          var_secinfos: [datasec_info]
        }

  @type float_type :: %{
          optional(:name) => String.t(),
          kind: :float,
          size: non_neg_integer
        }

  @type enum64_member :: %{
          optional(:name) => String.t(),
          val: integer,
          val_lo32: non_neg_integer,
          val_hi32: non_neg_integer
        }

  @type enum64_type :: %{
          optional(:name) => String.t(),
          kind: :enum64,
          kflag: 0 | 1,
          vlen: non_neg_integer,
          size: non_neg_integer,
          enum64: [enum64_member]
        }

  @type type ::
          int_type
          | ptr_type
          | array_type
          | struct_type
          | union_type
          | enum_type
          | fwd_type
          | typedef_type
          | volatile_type
          | const_type
          | restrict_type
          | func_type
          | func_proto_type
          | var_type
          | datasec_type
          | float_type
          | enum64_type

  @type endianness :: :little | :big

  @type t :: %__MODULE__{
          endianness: endianness,
          ref: reference()
        }

  @spec find_by_name(t, String.t()) :: {:ok, type} | :error
  def find_by_name(%__MODULE__{} = btf, name) when is_binary(name) do
    :bpf_sys.btf_find_by_name(btf.ref, name)
  end

  @spec find_by_name!(t, String.t()) :: type
  def find_by_name!(%__MODULE__{} = btf, name) when is_binary(name) do
    case :bpf_sys.btf_find_by_name(btf.ref, name) do
      {:ok, type} ->
        type

      :error ->
        raise BTF.Error,
          message: """
          Failed to find a BTF type with name #{inspect(name)}.
          """
    end
  end

  @spec find_by_id(t, type_id) :: {:ok, type} | :error
  def find_by_id(%__MODULE__{} = btf, id) when is_integer(id) do
    :bpf_sys.btf_find_by_id(btf.ref, id)
  end

  @spec find_by_id!(t, type_id) :: type
  def find_by_id!(%__MODULE__{} = btf, id) when is_integer(id) do
    case :bpf_sys.btf_find_by_id(btf.ref, id) do
      {:ok, type} ->
        type

      :error ->
        raise BTF.Error,
          message: """
          Failed to find a BTF type with id #{id}.
          """
    end
  end

  @spec encode(t, type, any) :: {:ok, binary} | {:error, any}
  def encode(%__MODULE__{} = btf, type, value) do
    btf
    |> BTF.Encoder.new()
    |> BTF.Encoder.encode(type, value)
  end

  @spec encode!(t, type, any) :: binary
  def encode!(%__MODULE__{} = btf, type, value) do
    case encode(btf, type, value) do
      {:ok, binary} ->
        binary

      {:error, reason} ->
        raise reason
    end
  end

  @spec decode(t, type, binary) :: {:ok, any} | {:error, any}
  def decode(%__MODULE__{} = btf, type, binary) do
    btf
    |> BTF.Decoder.new()
    |> BTF.Decoder.decode(type, binary)
  end

  @spec decode!(t, type, binary) :: any
  def decode!(%__MODULE__{} = btf, type, binary) do
    case decode(btf, type, binary) do
      {:ok, value} ->
        value

      {:error, reason} ->
        raise reason
    end
  end
end
