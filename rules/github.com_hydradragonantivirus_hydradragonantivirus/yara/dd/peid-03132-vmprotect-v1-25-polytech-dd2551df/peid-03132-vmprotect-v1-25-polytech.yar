rule PEiD_03132_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 59 5E 5D 5F 9D 5E 5B 58 C3 }

  condition:
    $a
}