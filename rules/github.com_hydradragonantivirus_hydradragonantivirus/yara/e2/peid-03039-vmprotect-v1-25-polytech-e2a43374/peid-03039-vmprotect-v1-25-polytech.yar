rule PEiD_03039_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 9D 5E 5D 58 5F 5A 59 5B C3 }

  condition:
    $a
}