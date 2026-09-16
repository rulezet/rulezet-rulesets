rule sig_20160826_fada7d508ffcc14bd2c7477739227089 {
  meta:
    description = "datamaliciousorder - file 20160826_fada7d508ffcc14bd2c7477739227089.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f7fe93dfe17e02176136e117046ddb3d5ae4d3c2ec70022bcd46207d31b639c"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}