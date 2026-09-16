rule PEiD_00824_FSG_v1_10__Eng_____dulek_xt_ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt]"
    ep_only     = "true"

  strings:
    $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }

  condition:
    $a
}