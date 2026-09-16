rule PEiD_01471_PC_Shrinker_v0_29_ {
  meta:
    description = "[PC Shrinker v0.29]"
    ep_only     = "true"

  strings:
    $a = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }

  condition:
    $a
}