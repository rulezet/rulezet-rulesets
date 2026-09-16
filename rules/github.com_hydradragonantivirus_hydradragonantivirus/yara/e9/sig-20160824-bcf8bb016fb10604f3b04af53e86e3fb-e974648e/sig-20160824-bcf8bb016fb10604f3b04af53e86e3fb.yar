rule sig_20160824_bcf8bb016fb10604f3b04af53e86e3fb {
  meta:
    description = "datamaliciousorder - file 20160824_bcf8bb016fb10604f3b04af53e86e3fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "814c5a1be3654f8938145f686f93e81854a07e86e7cce2bcd451452caf43e6e3"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}