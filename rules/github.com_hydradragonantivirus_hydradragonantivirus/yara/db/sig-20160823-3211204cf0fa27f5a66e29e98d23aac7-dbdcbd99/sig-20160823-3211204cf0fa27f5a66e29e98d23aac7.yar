rule sig_20160823_3211204cf0fa27f5a66e29e98d23aac7 {
  meta:
    description = "datamaliciousorder - file 20160823_3211204cf0fa27f5a66e29e98d23aac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e82472d4d4c9927d3550f1db01fd967b4103e52b1d3d4fce25e7fb9c875f23"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}