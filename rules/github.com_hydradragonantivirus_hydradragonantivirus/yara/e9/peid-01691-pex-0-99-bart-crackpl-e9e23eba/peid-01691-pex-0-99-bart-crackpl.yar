rule PEiD_01691_PeX_0_99____bart_CrackPl_ {
  meta:
    description = "[PeX 0.99 -> bart^CrackPl]"
    ep_only     = "true"

  strings:
    $a = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

  condition:
    $a
}