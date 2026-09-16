rule PEiD_00565_EXE_Shield_v0_1b___v0_3b__v0_3____SMoKE_ {
  meta:
    description = "[EXE Shield v0.1b - v0.3b, v0.3 -> SMoKE]"
    ep_only     = "true"

  strings:
    $a = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }

  condition:
    $a
}