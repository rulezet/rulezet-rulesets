rule sig_20160823_3e78943bf56de70c3212dcc1f4e81442 {
  meta:
    description = "datamaliciousorder - file 20160823_3e78943bf56de70c3212dcc1f4e81442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c131be1dca70f0a13e7688927007ce0f28c326008fcd0fa37111d11e7a407374"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}