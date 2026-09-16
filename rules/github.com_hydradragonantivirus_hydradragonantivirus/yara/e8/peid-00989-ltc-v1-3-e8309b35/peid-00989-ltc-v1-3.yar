rule PEiD_00989_LTC_v1_3_ {
  meta:
    description = "[LTC v1.3]"
    ep_only     = "true"

  strings:
    $a = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

  condition:
    $a
}