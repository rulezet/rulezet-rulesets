rule Trojan_Danger_Trojan_GenericKD_72677122_151_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11f4848ffa29b079f151b89e1cb95d23a290b7dcbee6dc7be43a572205b0166c"

  strings:
    $s1 = "Heap&Qu7" fullword ascii
    $s2 = "DISPLAY$6c" fullword ascii
    $s3 = "PHYSIC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}