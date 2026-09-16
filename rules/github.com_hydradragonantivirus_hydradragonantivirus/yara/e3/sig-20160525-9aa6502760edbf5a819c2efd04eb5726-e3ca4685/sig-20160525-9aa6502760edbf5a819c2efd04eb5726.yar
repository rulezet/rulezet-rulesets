rule sig_20160525_9aa6502760edbf5a819c2efd04eb5726 {
  meta:
    description = "datamaliciousorder - file 20160525_9aa6502760edbf5a819c2efd04eb5726.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d060672da22609e03cff2aade4135d033307c1c9701e4f79cd771be3aa9d55ec"

  strings:
    $s1 = "f(mf noitcnuf\\n;\"63x\\\\\" = keppelf rav\\n;\"27x\\\\C\" = ecapsetihwxelff rav\\n;\"f4x\\\\e47x\\\\16x\\\\56x\\\\\" = modnarf " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}