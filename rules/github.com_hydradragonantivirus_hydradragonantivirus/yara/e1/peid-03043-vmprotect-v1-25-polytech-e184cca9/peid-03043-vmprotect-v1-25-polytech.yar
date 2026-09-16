rule PEiD_03043_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 58 5A 5E 9D 5D 59 59 C3 }

  condition:
    $a
}