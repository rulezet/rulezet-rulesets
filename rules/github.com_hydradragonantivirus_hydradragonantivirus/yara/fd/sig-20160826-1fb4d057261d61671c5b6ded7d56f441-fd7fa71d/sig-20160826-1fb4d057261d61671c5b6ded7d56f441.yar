rule sig_20160826_1fb4d057261d61671c5b6ded7d56f441 {
  meta:
    description = "datamaliciousorder - file 20160826_1fb4d057261d61671c5b6ded7d56f441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df4bb7007e90757a5e42bd134e54f4c309694711c16933e4b439f10898ab7fe0"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}