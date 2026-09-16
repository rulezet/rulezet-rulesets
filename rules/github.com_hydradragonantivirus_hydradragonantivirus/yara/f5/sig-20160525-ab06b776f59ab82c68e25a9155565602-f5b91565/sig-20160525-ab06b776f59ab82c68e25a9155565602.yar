rule sig_20160525_ab06b776f59ab82c68e25a9155565602 {
  meta:
    description = "datamaliciousorder - file 20160525_ab06b776f59ab82c68e25a9155565602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcde7a11a980efaa6aba22bf77d2fa47cf4d40dac4f99d558878fd2519fbeae1"

  strings:
    $s1 = "ctho rav\\n;\"p56x\\\\\" = rerednero rav\\n;\"gn56x\\\\l\" = imo rav\\n;\"86x\\\\t\" = eixodp rav\\n;\"76x\\\\e6x\\\\el\" = gsmp" ascii
    $s2 = "darr noitcnuf;};suidarelcitrapr nruter{)suidarelcitrapr(gsmr noitcnuf\\n;\"tgn56x\\\\c6x\\\\\" = ecapsetihwxelfr rav\\n;\"86x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}