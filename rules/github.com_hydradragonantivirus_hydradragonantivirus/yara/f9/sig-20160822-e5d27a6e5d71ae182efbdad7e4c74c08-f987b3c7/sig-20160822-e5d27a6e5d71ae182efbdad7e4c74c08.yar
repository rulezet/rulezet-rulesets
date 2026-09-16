rule sig_20160822_e5d27a6e5d71ae182efbdad7e4c74c08 {
  meta:
    description = "datamaliciousorder - file 20160822_e5d27a6e5d71ae182efbdad7e4c74c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8094ac3717f5a053b8a259d87c5ec07e573bc23f730096f8765d07ada9495dd"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}