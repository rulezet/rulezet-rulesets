rule PEiD_03134_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 5D 59 5D 5F 58 5E 5B 9D C3 }

  condition:
    $a
}