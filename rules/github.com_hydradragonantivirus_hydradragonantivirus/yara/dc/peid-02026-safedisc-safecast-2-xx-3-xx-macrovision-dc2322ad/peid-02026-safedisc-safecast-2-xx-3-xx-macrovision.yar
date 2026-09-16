rule PEiD_02026_SafeDisc_SafeCast_2_xx___3_xx____Macrovision_ {
  meta:
    description = "[SafeDisc/SafeCast 2.xx - 3.xx -> Macrovision]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D 3D ?? ?? ?? 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 09 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 76 00 00 00 83 C4 08 59 83 F8 00 74 1C }

  condition:
    $a
}