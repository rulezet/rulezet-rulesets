rule sig_20160824_cdbfa5dd5054b99fd5e825ad90fb38c7 {
  meta:
    description = "datamaliciousorder - file 20160824_cdbfa5dd5054b99fd5e825ad90fb38c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89253b0650ac30af1e9eb1e117841fbe83f57bd0228b2313ecdf528333b2c7bc"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}