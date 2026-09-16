rule PEiD_01194_MSLRH_0_32a__fake_MSVC___6_0_DLL_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake MSVC++ 6.0 DLL) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 }

  condition:
    $a
}