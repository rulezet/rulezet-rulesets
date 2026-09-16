rule PEiD_03037_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5A 5F 5B 58 59 5D 9D 5D 5E C3 }

  condition:
    $a
}