rule sig_20160824_ca9a0a6e9a4fd4919d1360d739fce499 {
  meta:
    description = "datamaliciousorder - file 20160824_ca9a0a6e9a4fd4919d1360d739fce499.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecb796b27c429136c09c24d87c7513fa4e03de23c9c13b78dd478279d9933259"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}