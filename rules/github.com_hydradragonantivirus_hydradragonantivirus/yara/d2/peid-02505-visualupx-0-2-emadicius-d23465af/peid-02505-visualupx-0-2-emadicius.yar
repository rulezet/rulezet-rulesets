rule PEiD_02505_VisualUPX_0_2____emadicius_ {
  meta:
    description = "[VisualUPX 0.2 -> emadicius]"
    ep_only     = "true"

  strings:
    $a = { 66 C7 05 ?? ?? ?? 00 75 07 E9 ?? FE FF FF }

  condition:
    $a
}