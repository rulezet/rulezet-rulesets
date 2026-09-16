rule sig_20160823_8c0e338c7300832375a601688581d799 {
  meta:
    description = "datamaliciousorder - file 20160823_8c0e338c7300832375a601688581d799.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cd59887e0019456654ee7a413621a3321afa9480a47c229a477fba5973fb381"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}