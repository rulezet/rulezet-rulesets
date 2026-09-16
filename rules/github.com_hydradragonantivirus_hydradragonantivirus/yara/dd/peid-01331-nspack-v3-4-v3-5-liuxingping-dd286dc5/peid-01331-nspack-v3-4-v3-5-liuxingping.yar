rule PEiD_01331_NsPacK_V3_4_V3_5____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.4-V3.5 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }

  condition:
    $a
}