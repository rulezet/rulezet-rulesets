rule PEiD_01710_PKLITE_v1_12__v1_15__v1_20__2__ {
  meta:
    description = "[PKLITE v1.12, v1.15, v1.20 (2)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 3B C4 73 }

  condition:
    $a
}