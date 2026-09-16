rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "567e1d76d4c97a171991717d36f179fe6dd9af8286a44ecb51ff86d59764aa8d"

  strings:
    $s1 = "            <!--The ID below indicates application support for Windows BLUE -->" fullword ascii
    $s2 = "    <description>IE ETW Collector</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}