rule sig_20160822_2edf881f462b79d6beb1b75d99ed58d9 {
  meta:
    description = "datamaliciousorder - file 20160822_2edf881f462b79d6beb1b75d99ed58d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62d7015b4cc3982b745e908e6f8e92880fc8e96e1685297038ab19fb87bbe7b3"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}