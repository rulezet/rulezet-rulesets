rule sig_20160826_e1738ac496e4e0a53af5008b2bfc8757 {
  meta:
    description = "datamaliciousorder - file 20160826_e1738ac496e4e0a53af5008b2bfc8757.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6419f43edff6db21412804936ddc05f256c42a4e17d60d2d575db2e20d40e218"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}