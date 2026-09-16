rule PEiD_02677_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 52 55 9C 56 53 52 57 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 8D 0C 85 ?? ?? ?? ?? FF 21 89 EC 5A 58 5F 5A 5B 5E 9D 5D 59 59 C3 }

  condition:
    $a
}