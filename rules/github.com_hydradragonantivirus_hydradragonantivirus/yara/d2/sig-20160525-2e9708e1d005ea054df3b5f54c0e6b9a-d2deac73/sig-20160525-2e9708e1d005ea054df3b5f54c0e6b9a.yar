rule sig_20160525_2e9708e1d005ea054df3b5f54c0e6b9a {
  meta:
    description = "datamaliciousorder - file 20160525_2e9708e1d005ea054df3b5f54c0e6b9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adc6355d2a6e4006e3423902857e425ef23158e0e1346074ae4c8586cd0014f9"

  strings:
    $s1 = " tsilslianbmuhtoj rav\\n;\"p56x\\\\\" = cthj rav;};gedotdark nruter{)gedotdark(mk noitcnuf;};dnenoisillock nruter{)dnenoisillock" ascii
    $s2 = "darg rav\\n;\"56x\\\\t\" = keppelg rav\\n;\"jbf4x\\\\\" = ecapsetihwxelfg rav\\n;\"tc56x\\\\\" = modnarg rav;};gedotdarh nruter{" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}