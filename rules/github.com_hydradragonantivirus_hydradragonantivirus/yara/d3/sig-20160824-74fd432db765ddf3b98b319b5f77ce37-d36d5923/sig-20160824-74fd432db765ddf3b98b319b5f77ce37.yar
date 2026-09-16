rule sig_20160824_74fd432db765ddf3b98b319b5f77ce37 {
  meta:
    description = "datamaliciousorder - file 20160824_74fd432db765ddf3b98b319b5f77ce37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "216f2d2ac133086711a48010042b0e0b1cc0a9309cdca3e023e6a72eab944967"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}