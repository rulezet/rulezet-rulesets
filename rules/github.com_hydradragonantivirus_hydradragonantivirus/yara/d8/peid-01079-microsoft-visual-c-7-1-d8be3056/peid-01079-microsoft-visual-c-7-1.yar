rule PEiD_01079_Microsoft_Visual_C___7_1_ {
  meta:
    description = "[Microsoft Visual C++ 7.1]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 EC 08 53 56 57 55 FC 8B 5D 0C 8B 45 08 F7 40 04 06 00 00 00 0F 85 AB 00 00 00 89 45 F8 8B 45 10 89 45 FC 8D 45 F8 89 43 FC 8B 73 0C 8B 7B 08 53 E8 ?? ?? ?? ?? 83 C4 04 0B C0 74 7B 83 FE FF 74 7D 8D 0C 76 8B 44 8F 04 0B C0 74 59 56 55 }

  condition:
    $a
}