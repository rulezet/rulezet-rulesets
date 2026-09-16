rule sig_20160525_526970323290f674fbaac1f151e06f39 {
  meta:
    description = "datamaliciousorder - file 20160525_526970323290f674fbaac1f151e06f39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e05ef0c4539f2ad707195543348d81ceb9843bed0ee1434f3a3a2bd30c3a2943"

  strings:
    $s1 = "loch noitcnuf([rerednera[rerednera = /*  Axy KKa IlC */ sdnet rav" fullword ascii
    $s2 = "rapt + ))(};gsmt nruter{)(mt noitcnuf([eixodb    \\n;)(])deerdi(reredneri + )modnari(tsilslianbmuhtoi[eixodb    \\n         ;mb " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}