rule PEiD_03306_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9C 52 51 56 57 50 50 53 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 FF 24 85 ?? ?? ?? ?? 8B 45 00 8A 55 04 83 C5 06 88 10 E9 }

  condition:
    $a
}