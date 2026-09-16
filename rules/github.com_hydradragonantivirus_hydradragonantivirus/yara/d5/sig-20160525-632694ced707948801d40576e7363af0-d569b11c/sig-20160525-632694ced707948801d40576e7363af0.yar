rule sig_20160525_632694ced707948801d40576e7363af0 {
  meta:
    description = "datamaliciousorder - file 20160525_632694ced707948801d40576e7363af0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eabedcfb4db7513721621d1d9a2991d02efbd87c2119ad97e21f0a3eab0c5b2b"

  strings:
    $s1 = "\\n;)eixodl + ))(};imk nruter{)(gedotdarl noitcnuf( + rerednerk + cthk(]eixodf + ))(};ime nruter{)(mf noitcnuf( + )rerednere(sui" ascii
    $s2 = "v;\"kceKHB\" = cthl rav\\n;\"s56x\\\\R\" = gsmm rav\\n;\"no07x\\\\\" = suidarelcitrapm rav\\n;\"doB56x\\\\37x\\\\\" = dnenoisill" ascii
    $s3 = "darn rav\\n;\"O44x\\\\A\" = sdnetn rav\\n;\"47x\\\\35x\\\\.BD\" = ssorcan rav\\n;\"d6x\\\\a56x\\\\r\" = tsilslianbmuhton rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}