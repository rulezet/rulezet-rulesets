rule sig_20160824_fb1556d6eae2f79e9b86f84f2f21bb66 {
  meta:
    description = "datamaliciousorder - file 20160824_fb1556d6eae2f79e9b86f84f2f21bb66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d175a0f182ef2ed7184e756814dc24a6528179e7ac329410dd007e30e6fac1d7"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}