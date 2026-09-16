rule sig_20160525_8483cb9c4c7b2a38768ae4799fa44061 {
  meta:
    description = "datamaliciousorder - file 20160525_8483cb9c4c7b2a38768ae4799fa44061.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b04b077602f94a6013d26090328c1e8f5a653e5e92f2b96bea6616ae4f16299d"

  strings:
    $s1 = "nruter{)ecapsetihwxelfl(keppell noitcnuf;};gedotdarl nruter{)gedotdarl(ml noitcnuf\\n;\"v16x\\\\S\" = modnarl rav\\n;\"Ff6x\\\\T" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}