rule PEiD_01900_PuNkMoD_1_x____PuNkDuDe_ {
  meta:
    description = "[PuNkMoD 1.x -> PuNkDuDe]"
    ep_only     = "true"

  strings:
    $a = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }

  condition:
    $a
}