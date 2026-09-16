rule sig_20160823_8e8265dc9af850b183a9c0bcd67efdcb {
  meta:
    description = "datamaliciousorder - file 20160823_8e8265dc9af850b183a9c0bcd67efdcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "853003d8b8cc35f898a297f7e0c5c15170c9d3b65ea001530d7a3efa101aafa1"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}