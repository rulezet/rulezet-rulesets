rule sig_20160826_7f114d056541207e94db2d35aa5f69cb {
  meta:
    description = "datamaliciousorder - file 20160826_7f114d056541207e94db2d35aa5f69cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8637d75e406f45c01d58f4b65e4f17496f394fb85cc74552e22184564a053586"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}