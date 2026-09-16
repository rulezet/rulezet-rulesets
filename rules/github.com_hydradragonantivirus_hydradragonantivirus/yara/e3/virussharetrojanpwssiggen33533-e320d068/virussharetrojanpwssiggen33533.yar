rule VirusShareTrojanPWSSiggen33533 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSSiggen33533.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf207915ec2e97d953377550830acaee270b861bc304129a726515d01779f612"

  strings:
    $s1 = "London Jamocha Community CIC0" fullword ascii
    $s2 = "London Jamocha Community CIC1%0#" fullword ascii
    $s3 = "boRH$\"" fullword ascii
    $s4 = "pEal}~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}