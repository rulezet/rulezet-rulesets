rule PEiD_01157_MoleBox_V2_X____MoleStudio_com_ {
  meta:
    description = "[MoleBox V2.X -> MoleStudio.com]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 60 E8 4F 00 00 00 }

  condition:
    $a
}