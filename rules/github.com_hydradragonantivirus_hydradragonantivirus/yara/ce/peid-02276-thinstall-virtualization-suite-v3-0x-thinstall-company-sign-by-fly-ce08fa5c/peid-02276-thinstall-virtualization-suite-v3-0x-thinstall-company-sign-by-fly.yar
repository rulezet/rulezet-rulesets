rule PEiD_02276_Thinstall_Virtualization_Suite_V3_0X____Thinstall_Company___Sign_by_fly_ {
  meta:
    description = "[Thinstall Virtualization Suite V3.0X -> Thinstall Company ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF 00 00 00 73 1B 55 BD ?? ?? ?? ?? E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

  condition:
    $a
}