rule Upx_Lock1_0_1_2__CyberDoom_Team_X_BoB_TeamPEiD {
  meta:
    author      = "PEiD"
    description = "Upx-Lock 1.0 - 1.2 -> CyberDoom / Team-X + BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

  condition:
    $a0
}