rule sig_20160824_7c8175fd04b2c90bf20e95dbb6b97579 {
  meta:
    description = "datamaliciousorder - file 20160824_7c8175fd04b2c90bf20e95dbb6b97579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c6686a55cf5284567b4287c1f8bab78ecf4b645dd7659a3fba66f40281745f"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}