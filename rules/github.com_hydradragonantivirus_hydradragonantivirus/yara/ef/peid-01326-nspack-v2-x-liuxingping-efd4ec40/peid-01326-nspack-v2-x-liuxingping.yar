rule PEiD_01326_NsPack_V2_X____LiuXingPing_ {
  meta:
    description = "[NsPack V2.X -> LiuXingPing]"
    ep_only     = "false"

  strings:
    $a = "nspack$@"

  condition:
    $a
}