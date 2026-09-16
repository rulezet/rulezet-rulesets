rule PEiD_01490_PE_Diminisher_V0_1____Teraphy_ {
  meta:
    description = "[PE Diminisher V0.1 -> Teraphy]"
    ep_only     = "true"

  strings:
    $a = { 53 51 52 56 57 55 E8 00 00 00 00 }

  condition:
    $a
}