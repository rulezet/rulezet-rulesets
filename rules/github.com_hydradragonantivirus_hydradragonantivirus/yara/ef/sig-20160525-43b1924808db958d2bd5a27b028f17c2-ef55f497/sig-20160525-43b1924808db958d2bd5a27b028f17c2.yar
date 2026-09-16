rule sig_20160525_43b1924808db958d2bd5a27b028f17c2 {
  meta:
    description = "datamaliciousorder - file 20160525_43b1924808db958d2bd5a27b028f17c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dd6bc6312667a0354f9bfe0ea55685ac07f8184add17d4453da3ce95671cad2"

  strings:
    $s1 = "ruter{)cthd(tsilslianbmuhtod noitcnuf\\n;\"47x\\\\h\" = rerednerd rav\\n;\"p47x\\\\\" = imd rav\\n;\"16x\\\\g//:\" = gsme rav\\n" ascii
    $s2 = " rav\\n;\"m56x\\\\\" = eixodc rav\\n;)2(]\"tAra\"+\"86x\\\\\"+\"c\"[imb = gsmc rav;\"kd5B\" = imb rav\\n;\"r96x\\\\\" = dnenoisi" ascii
    $s3 = "dare = ecapsetihwxelfe rav;\"/0\" = gedotdare rav\\n;\"47x\\\\713x\\\\\" = modnare rav\\n;\"23x\\\\\" = deerde rav;};ssorcae nru" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}