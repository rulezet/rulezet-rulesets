rule PEiD_01039_Microsoft_C__1990_1992__ {
  meta:
    description = "[Microsoft C (1990/1992)]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 }

  condition:
    $a
}