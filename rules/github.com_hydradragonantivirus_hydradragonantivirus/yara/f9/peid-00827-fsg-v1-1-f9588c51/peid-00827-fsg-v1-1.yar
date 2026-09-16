rule PEiD_00827_FSG_v1_1_ {
  meta:
    description = "[FSG v1.1]"
    ep_only     = "true"

  strings:
    $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

  condition:
    $a
}