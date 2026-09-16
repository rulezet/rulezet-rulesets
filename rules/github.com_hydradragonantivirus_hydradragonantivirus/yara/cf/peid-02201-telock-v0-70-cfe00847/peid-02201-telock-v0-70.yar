rule PEiD_02201_tElock_v0_70_ {
  meta:
    description = "[tElock v0.70]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

  condition:
    $a
}