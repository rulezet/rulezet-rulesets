rule PEiD_00218_ASPack_v1_08_01_ {
  meta:
    description = "[ASPack v1.08.01]"
    ep_only     = "true"

  strings:
    $a = { 90 90 75 ?? 90 E9 }

  condition:
    $a
}