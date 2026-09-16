rule PEiD_01635_PESHiELD_v0_25_ {
  meta:
    description = "[PESHiELD v0.25]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 2B 00 00 00 }

  condition:
    $a
}