rule PEiD_02032_SCRAM__v0_8a1_ {
  meta:
    description = "[SCRAM! v0.8a1]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C }

  condition:
    $a
}