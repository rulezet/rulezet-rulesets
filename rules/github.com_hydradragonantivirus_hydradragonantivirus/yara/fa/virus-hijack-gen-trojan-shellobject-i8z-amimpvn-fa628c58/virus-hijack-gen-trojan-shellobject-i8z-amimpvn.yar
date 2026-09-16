rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3896d364ae4a278cbc752ddb9272509e01d8f3ff80fdd0d25545dd4a79c0a61f"

  strings:
    $s1 = "3policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}