import "pe"
rule PEiD_00386_CodeCrypt_v0_14b_ {
  meta:
    description = "[CodeCrypt v0.14b]"
    ep_only     = "true"

  strings:
    $a = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

  condition:
    $a at pe.entry_point
}