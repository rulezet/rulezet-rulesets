rule sig_20170119_1954ad79e35cc13f0f0643a3cbaf2c60 {
  meta:
    description = "datamaliciousorder - file 20170119_1954ad79e35cc13f0f0643a3cbaf2c60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b19191a8633f87fc4c6cc2b920ecd0138723209d3b5bedb7abc0b6ae986d299c"

  strings:
    $s1 = "var yfyw7 = new Function(adcejvinysezexecbortywyzamizoxtohimijmuflovixmyzixxiswakmifteqkikakcelezfobibenveqpozykdegpattokxydzamw" ascii
    $s2 = "var yfyw7 = new Function(adcejvinysezexecbortywyzamizoxtohimijmuflovixmyzixxiswakmifteqkikakcelezfobibenveqpozykdegpattokxydzamw" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}