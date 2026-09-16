rule sig_20160525_fc9e20b038dab248520ae53ccb0744c9 {
  meta:
    description = "datamaliciousorder - file 20160525_fc9e20b038dab248520ae53ccb0744c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa9adf608569d91b60a6358fc7be8a1fb0fce456098a85848e7ca98c76473993"

  strings:
    $s1 = "(eixodj noitcnuf;};imi nruter{)imi(reredneri noitcnuf;};cthi nruter{)cthi(tsilslianbmuhtoi noitcnuf;};sdneti nruter{)sdneti(deer" ascii
    $s2 = "en\\\\r\\\\\" = ctho rav\\n;\"96x\\\\so07x\\\\\" = rerednero rav\\n;\"e6x\\\\o96x\\\\t\" = imo rav\\n;\"Teva35x\\\\\" = gsmp rav" ascii
    $s3 = "nete rav\\n;\"13x\\\\r\" = ssorcae rav\\n;\"03x\\\\d\" = tsilslianbmuhtoe rav\\n;\"o66x\\\\\" = cthe rav\\n;\"xd6x\\\\\" = rered" ascii
    $s4 = "lock rav\\n;\"e27x\\\\34x\\\\\" = ecapsetihwxelfk rav\\n;\"bO56x\\\\ta\" = modnark rav\\n;\"c56x\\\\j\" = deerdk rav\\n;\"47x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}