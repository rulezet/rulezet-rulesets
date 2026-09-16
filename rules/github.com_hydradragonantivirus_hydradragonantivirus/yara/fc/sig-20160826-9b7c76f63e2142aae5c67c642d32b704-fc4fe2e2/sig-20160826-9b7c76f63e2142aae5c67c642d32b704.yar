rule sig_20160826_9b7c76f63e2142aae5c67c642d32b704 {
  meta:
    description = "datamaliciousorder - file 20160826_9b7c76f63e2142aae5c67c642d32b704.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4932eab2a8fe6ee386c7594a788793d9942861127a0bd701709b228c97526a00"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}