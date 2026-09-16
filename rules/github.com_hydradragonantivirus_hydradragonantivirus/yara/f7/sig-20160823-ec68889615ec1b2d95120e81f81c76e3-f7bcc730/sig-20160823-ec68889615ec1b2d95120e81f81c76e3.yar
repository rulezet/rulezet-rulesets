rule sig_20160823_ec68889615ec1b2d95120e81f81c76e3 {
  meta:
    description = "datamaliciousorder - file 20160823_ec68889615ec1b2d95120e81f81c76e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28246a3e0915576ded613f5d3a694cabdc138b36df05de6bae7608f2351b381a"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}