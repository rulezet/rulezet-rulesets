rule sig_20160824_e7483ef662335ccbb8c04fdaee1237c1 {
  meta:
    description = "datamaliciousorder - file 20160824_e7483ef662335ccbb8c04fdaee1237c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "752c00500810fa84b4c92ae37e348922de4ecd0e1431a5143cc81f03b3efdf2a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}