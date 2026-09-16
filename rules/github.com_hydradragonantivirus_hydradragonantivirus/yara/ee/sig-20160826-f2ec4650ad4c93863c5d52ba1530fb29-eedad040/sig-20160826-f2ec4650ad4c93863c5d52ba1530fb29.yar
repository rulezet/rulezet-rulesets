rule sig_20160826_f2ec4650ad4c93863c5d52ba1530fb29 {
  meta:
    description = "datamaliciousorder - file 20160826_f2ec4650ad4c93863c5d52ba1530fb29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8fad9d14612445d9e799f23e981d8afa1cb266544252f4e2baaaa86b0bdc254"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}