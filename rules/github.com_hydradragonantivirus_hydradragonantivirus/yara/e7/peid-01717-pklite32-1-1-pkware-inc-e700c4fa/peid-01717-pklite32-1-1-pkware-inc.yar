rule PEiD_01717_PKLITE32_1_1____PKWARE_Inc__ {
  meta:
    description = "[PKLITE32 1.1 -> PKWARE Inc.]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9 }

  condition:
    $a
}