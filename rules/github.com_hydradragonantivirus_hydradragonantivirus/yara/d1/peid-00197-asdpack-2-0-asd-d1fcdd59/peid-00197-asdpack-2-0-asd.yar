rule PEiD_00197_ASDPack_2_0____asd_ {
  meta:
    description = "[ASDPack 2.0 -> asd]"
    ep_only     = "false"

  strings:
    $a = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }

  condition:
    $a
}