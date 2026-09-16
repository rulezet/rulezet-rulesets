rule PEiD_02820_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 56 52 57 50 55 53 9C 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8A 06 46 83 ED 02 66 89 45 00 E9 }

  condition:
    $a
}