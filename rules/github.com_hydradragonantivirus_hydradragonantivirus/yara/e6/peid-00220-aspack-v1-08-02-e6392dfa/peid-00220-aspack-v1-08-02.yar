rule PEiD_00220_ASPack_v1_08_02_ {
  meta:
    description = "[ASPack v1.08.02]"
    ep_only     = "true"

  strings:
    $a = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }

  condition:
    $a
}