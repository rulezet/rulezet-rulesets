rule PEiD_03335_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 55 00 66 8B 45 00 83 ED 02 66 21 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}