rule PEiD_01066_Microsoft_Visual_C___6_0___8_0_ {
  meta:
    description = "[Microsoft Visual C++ 6.0 - 8.0]"
    ep_only     = "false"

  strings:
    $a = { 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 C3 }

  condition:
    $a
}