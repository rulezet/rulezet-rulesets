rule sig_20160525_021ee2d74a891e270e1c70a8d5105adf {
  meta:
    description = "datamaliciousorder - file 20160525_021ee2d74a891e270e1c70a8d5105adf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cca1db7b8b17e9112a74d32231a9982d374b9b2021ba9ab4af0bc418364ddbd9"

  strings:
    $s1 = "loca rav" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}