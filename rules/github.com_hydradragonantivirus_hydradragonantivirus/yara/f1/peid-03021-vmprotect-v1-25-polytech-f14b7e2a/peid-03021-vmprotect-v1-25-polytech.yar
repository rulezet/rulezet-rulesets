rule PEiD_03021_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5F 5D 5E 5B 58 59 5A 59 C3 }

  condition:
    $a
}