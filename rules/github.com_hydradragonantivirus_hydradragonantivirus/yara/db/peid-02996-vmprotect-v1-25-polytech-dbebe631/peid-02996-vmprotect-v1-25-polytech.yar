rule PEiD_02996_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5B 9D 5E 5A 5E 59 5F 5D 58 C3 }

  condition:
    $a
}