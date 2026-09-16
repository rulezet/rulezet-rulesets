rule sig_20160824_d9332406bb4900d75af73c5f350d939a {
  meta:
    description = "datamaliciousorder - file 20160824_d9332406bb4900d75af73c5f350d939a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df060c26eae20bbc898f0a21d84d8b3e928b9cc2354b2b0471492cff46241ab"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}