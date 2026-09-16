rule Virus_Hijack_Trojan_GenericKDZ_98113_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a42b318c2e47024c0494c81435d39f4b47cb8962f2ec21b7d8b3af023db3e913"

  strings:
    $s1 = "TO RESOLVE A DISPUTE WITH THE MA NUFA CTURER OR INSTALLER, OR`" fullword ascii
    $s2 = "\\your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}