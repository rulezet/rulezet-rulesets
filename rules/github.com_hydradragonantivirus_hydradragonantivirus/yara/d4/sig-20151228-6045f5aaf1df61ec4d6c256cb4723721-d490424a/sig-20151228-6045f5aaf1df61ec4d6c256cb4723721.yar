rule sig_20151228_6045f5aaf1df61ec4d6c256cb4723721 {
  meta:
    description = "datamaliciousorder - file 20151228_6045f5aaf1df61ec4d6c256cb4723721.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91b461bb5464208ee63a2dd9ad01a8216a0db42b72176204b5b4c2e9e86cc374"

  strings:
    $s1 = "print (axbmfdvkp);" fullword ascii
    $s2 = "//}else{" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}