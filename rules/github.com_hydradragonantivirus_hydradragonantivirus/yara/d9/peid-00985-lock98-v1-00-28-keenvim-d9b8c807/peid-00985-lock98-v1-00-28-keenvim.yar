rule PEiD_00985_LOCK98_V1_00_28____keenvim_ {
  meta:
    description = "[LOCK98 V1.00.28 -> keenvim]"
    ep_only     = "true"

  strings:
    $a = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }

  condition:
    $a
}