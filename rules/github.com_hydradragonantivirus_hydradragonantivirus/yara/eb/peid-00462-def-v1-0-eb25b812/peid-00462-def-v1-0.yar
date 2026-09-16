rule PEiD_00462_DEF_v1_0_ {
  meta:
    description = "[DEF v1.0]"
    ep_only     = "true"

  strings:
    $a = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }

  condition:
    $a
}