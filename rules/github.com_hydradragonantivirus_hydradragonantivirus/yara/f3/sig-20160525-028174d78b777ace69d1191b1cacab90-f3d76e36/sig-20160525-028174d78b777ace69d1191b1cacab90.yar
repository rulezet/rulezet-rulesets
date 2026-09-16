rule sig_20160525_028174d78b777ace69d1191b1cacab90 {
  meta:
    description = "datamaliciousorder - file 20160525_028174d78b777ace69d1191b1cacab90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d332c5396218f5178a253f2a8c61af74ef7c4a6fdb82c547d2b8757ea4084f6"

  strings:
    $s1 = "\\n;))keppell(deerdl + gedotdarl + ml + ))(};dnenoisillocl nruter{)(modnarl noitcnuf( + suidarelcitrapl(]ssorcaf + sdnetf + )dee" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}