rule PEiD_01332_NsPacK_V3_6____LiuXingPing_ {
  meta:
    description = "[NsPacK V3.6 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }

  condition:
    $a
}