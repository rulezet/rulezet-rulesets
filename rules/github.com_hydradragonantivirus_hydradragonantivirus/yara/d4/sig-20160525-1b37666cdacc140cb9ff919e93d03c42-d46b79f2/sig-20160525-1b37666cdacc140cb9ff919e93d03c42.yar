rule sig_20160525_1b37666cdacc140cb9ff919e93d03c42 {
  meta:
    description = "datamaliciousorder - file 20160525_1b37666cdacc140cb9ff919e93d03c42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6f0f7f60904f821f1b13828cbf13f5073b176adae6c0da821df44b2353f19d"

  strings:
    $s1 = "cb = modnar rav\\n;)eixodh + img + rerednerg + cthg(]keppelg + gedotdarg + mg + dnenoisillocg[tpircSW = dnenoisillocb rav\\n;]su" ascii
    $s2 = " = gedotdars rav;};ecapsetihwxelfs nruter{)ecapsetihwxelfs(keppels noitcnuf\\n;\"16x\\\\e25x\\\\\" = modnars rav\\n;\"56x\\\\T46" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}