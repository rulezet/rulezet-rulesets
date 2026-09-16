rule sig_20160525_cd9dd27982d6456e476bc8f8618df94b {
  meta:
    description = "datamaliciousorder - file 20160525_cd9dd27982d6456e476bc8f8618df94b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9349b491b809a5481211c9f1fcca8b6b20310337916458758648bdcbfb61c533"

  strings:
    $s1 = "odnarj + ))(};ecapsetihwxelfj nruter{)(sdnetj noitcnuf( + ))(};keppelj nruter{)(deerdj noitcnuf( ,mj + dnenoisillocj + ))(};suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}