rule PEiD_02703_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 9C 56 50 52 57 57 55 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 46 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }

  condition:
    $a
}