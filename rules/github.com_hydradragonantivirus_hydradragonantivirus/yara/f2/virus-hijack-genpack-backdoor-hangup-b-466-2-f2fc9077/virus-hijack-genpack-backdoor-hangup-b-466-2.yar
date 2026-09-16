rule Virus_Hijack_GenPack_Backdoor_Hangup_B_466_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_466_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a774827dbdebec56fcb849bef9c11d82314bce71ad2406fc9a44d82a826b2633"

  strings:
    $s1 = "@System@@LStrToPChar$qqrx17System@AnsiString" fullword ascii
    $s2 = "@Parser@Finalization$qqrv" fullword ascii
    $s3 = "@Suiform@Finalization$qqrv" fullword ascii
    $s4 = "@Suiform@initialization$qqrv" fullword ascii
    $s5 = "@Parser@initialization$qqrv" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}