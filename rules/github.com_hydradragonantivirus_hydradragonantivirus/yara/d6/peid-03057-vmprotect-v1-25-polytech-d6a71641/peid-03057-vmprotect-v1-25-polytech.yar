rule PEiD_03057_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5E 5D 5A 5F 59 58 9D 5B 5B C3 }

  condition:
    $a
}