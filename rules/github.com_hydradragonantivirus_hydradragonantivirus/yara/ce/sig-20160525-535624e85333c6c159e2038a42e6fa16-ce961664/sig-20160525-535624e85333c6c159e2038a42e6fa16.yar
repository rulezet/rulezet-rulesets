rule sig_20160525_535624e85333c6c159e2038a42e6fa16 {
  meta:
    description = "datamaliciousorder - file 20160525_535624e85333c6c159e2038a42e6fa16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef93a8385c50714546ab4251ac9439359da68bde8132bbe8dba5306fa662fe89"

  strings:
    $s1 = "capsetihwxelfj + keppelj + gedotdarj + mj + )dnenoisillocj(modnarj ,imi + reredneri + cthi + ))(};tsilslianbmuhtoi nruter{)(suid" ascii
    $s2 = "\\\\daoL\" = ms rav\\n;\"o27x\\\\\" = gedotdars rav\\n;\"i64x\\\\d6x\\\\\" = keppels rav\\n;\"ec6x\\\\\" = ecapsetihwxelfs rav;}" ascii
    $s3 = "darn rav;};ecapsetihwxelfn nruter{)ecapsetihwxelfn(keppeln noitcnuf\\n;\"sf6x\\\\p\" = modnarn rav\\n;\"e6x\\\\oiti\" = deerdn r" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}