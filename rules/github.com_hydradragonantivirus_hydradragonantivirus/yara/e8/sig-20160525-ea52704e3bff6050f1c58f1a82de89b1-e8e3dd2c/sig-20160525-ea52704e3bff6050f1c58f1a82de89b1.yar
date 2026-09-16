rule sig_20160525_ea52704e3bff6050f1c58f1a82de89b1 {
  meta:
    description = "datamaliciousorder - file 20160525_ea52704e3bff6050f1c58f1a82de89b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01b6f47041b0437e778cc2bc055f612472c019aef1400d57f6d7558ef78bc631"

  strings:
    $s1 = "rb+cthb + tsilslianbmuhtob+)deerdb(sdnetb + modnarb+ecapsetihwxelfb+keppelb[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- =" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}