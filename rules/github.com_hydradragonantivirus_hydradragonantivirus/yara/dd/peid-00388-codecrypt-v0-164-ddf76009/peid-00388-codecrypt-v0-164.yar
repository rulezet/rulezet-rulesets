import "pe"
rule PEiD_00388_CodeCrypt_v0_164_ {
  meta:
    description = "[CodeCrypt v0.164]"
    ep_only     = "true"

  strings:
    $a = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

  condition:
    $a at pe.entry_point
}