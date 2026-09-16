rule PEiD_00230_ASPack_v1_08_ {
  meta:
    description = "[ASPack v1.08]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 75 01 FF E9 }

  condition:
    $a
}