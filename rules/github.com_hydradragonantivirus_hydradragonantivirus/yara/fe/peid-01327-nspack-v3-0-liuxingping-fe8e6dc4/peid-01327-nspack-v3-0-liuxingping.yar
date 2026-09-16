rule PEiD_01327_NsPacK_V3_0____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.0 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }

  condition:
    $a
}