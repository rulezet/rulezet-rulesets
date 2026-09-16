rule sig_20161024_9781da1b160133fe8b84882a55062ba5 {
  meta:
    description = "datamaliciousorder - file 20161024_9781da1b160133fe8b84882a55062ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24bada96a9575ecae925449845f03068ec00474e73f4a2c44628d5b46029fdca"

  strings:
    $s1 = "} while (ua++ < le0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}