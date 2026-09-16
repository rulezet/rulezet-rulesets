rule Virus_Hooker_Gen_Variant_Downloader_251 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Downloader.251.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8ac5b9c887157b9ec001732adfd8a5f7155c1c52a72acb29bb8fe353e4481a4"

  strings:
    $s1 = "System informations not available!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}