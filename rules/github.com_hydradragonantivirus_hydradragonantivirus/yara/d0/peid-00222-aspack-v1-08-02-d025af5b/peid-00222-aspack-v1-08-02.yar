rule PEiD_00222_ASPack_v1_08_02_ {
  meta:
    description = "[ASPack v1.08.02]"
    ep_only     = "true"

  strings:
    $a = { 90 75 01 90 E9 }

  condition:
    $a
}