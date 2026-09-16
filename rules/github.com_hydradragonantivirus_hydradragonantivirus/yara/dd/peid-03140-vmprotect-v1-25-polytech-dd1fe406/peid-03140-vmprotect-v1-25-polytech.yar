rule PEiD_03140_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5B 5D 5E 5F 58 9D 5A 58 59 C3 }

  condition:
    $a
}