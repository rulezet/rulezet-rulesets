rule Trojan_Hooker_Gen_Trojan_ProcessHijack_4s3baGODL8ai_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Trojan.ProcessHijack.4s3baGODL8ai_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df24cf421dd6852f0220db9399fe47f863bc13fa115b6fc8b4a90abfe4c955f7"

  strings:
    $s1 = "SECURE APPLICATION DEVELOPMENT1)0'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}