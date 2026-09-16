rule sig_20160525_00f59705aa7debbe348cf32aeeb737ec {
  meta:
    description = "datamaliciousorder - file 20160525_00f59705aa7debbe348cf32aeeb737ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dd1c333d77286eea03f3a5fd04d2281f97e9f8dd3f44ae067ea0ef4f8aee4ba"

  strings:
    $s1 = "\\n;\"ht76x\\\\\" = cthj rav\\n;\"56x\\\\lS\" = rerednerj rav\\n;\"07x\\\\e\" = imj rav;};gsmk nruter{)gsmk(eixodk noitcnuf\\n;" ascii
    $s2 = "av\\n;\"r34x\\\\\" = keppels rav\\n;\"e47x\\\\16x\\\\e\" = ecapsetihwxelfs rav\\n;\"a6x\\\\bO\" = modnars rav\\n;\"36x\\\\e\" = " ascii
    $s3 = "ssorcac = tsilslianbmuhtoc rav;\"e\" = ssorcac rav;};rerednerc nruter{)rerednerc(cthc noitcnuf\\n;\"t86x\\\\\" = eixodd rav\\n;)" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}