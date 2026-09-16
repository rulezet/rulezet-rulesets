rule PEiD_00677_eXPressor_V1_0____CGSoftLabs_ {
  meta:
    description = "[eXPressor V1.0 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }

  condition:
    $a
}