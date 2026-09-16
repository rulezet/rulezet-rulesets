rule PEiD_03411_Vx__Phoenix_927_ {
  meta:
    description = "[Vx: Phoenix.927]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }

  condition:
    $a
}