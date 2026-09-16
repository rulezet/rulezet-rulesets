rule sig_20160826_1bd22f2acd11e3d5f8450450bad4491a {
  meta:
    description = "datamaliciousorder - file 20160826_1bd22f2acd11e3d5f8450450bad4491a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9753279279e10b33914a7ec4fd6b0109741e2b0ca3d6da2b2d1984254f3d8e6"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}