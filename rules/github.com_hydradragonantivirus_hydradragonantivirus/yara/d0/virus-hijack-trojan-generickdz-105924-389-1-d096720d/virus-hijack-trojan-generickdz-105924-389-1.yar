rule Virus_Hijack_Trojan_GenericKDZ_105924_389_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c62b9dfb1b772658f0691525d18e3ed6c9f97be443452d97bdbc381ed71af513"

  strings:
    $s1 = ">AnsU@72EZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}