rule PEiD_03013_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5F 5B 5E 5B 5D 59 5A 9D 58 C3 }

  condition:
    $a
}