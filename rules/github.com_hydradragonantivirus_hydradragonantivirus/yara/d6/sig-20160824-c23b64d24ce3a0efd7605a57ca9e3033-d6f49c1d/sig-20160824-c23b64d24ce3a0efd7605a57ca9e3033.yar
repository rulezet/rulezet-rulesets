rule sig_20160824_c23b64d24ce3a0efd7605a57ca9e3033 {
  meta:
    description = "datamaliciousorder - file 20160824_c23b64d24ce3a0efd7605a57ca9e3033.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24f5747f545d044f5e0bd51c37041af34c7dbe910cfaa8a31887ff517cdbd712"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}