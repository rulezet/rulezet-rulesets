rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "241f55cdae560a9407eeb166879a3c6503db136ec2c2dc44e367735ece5f4961"

  strings:
    $s1 = "UTmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}