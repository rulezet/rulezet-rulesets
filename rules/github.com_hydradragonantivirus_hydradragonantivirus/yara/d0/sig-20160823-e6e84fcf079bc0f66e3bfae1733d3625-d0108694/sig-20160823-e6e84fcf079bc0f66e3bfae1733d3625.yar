rule sig_20160823_e6e84fcf079bc0f66e3bfae1733d3625 {
  meta:
    description = "datamaliciousorder - file 20160823_e6e84fcf079bc0f66e3bfae1733d3625.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69014325dae931ab6f48061b1885e8f9a061b2cc2749b4164b0468f4bcff0eaf"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}