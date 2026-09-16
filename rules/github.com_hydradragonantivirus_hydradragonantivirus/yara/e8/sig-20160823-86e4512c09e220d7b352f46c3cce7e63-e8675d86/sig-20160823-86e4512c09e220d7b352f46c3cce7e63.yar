rule sig_20160823_86e4512c09e220d7b352f46c3cce7e63 {
  meta:
    description = "datamaliciousorder - file 20160823_86e4512c09e220d7b352f46c3cce7e63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a0d52427d926e0fbf5411557a23aa3fb7b3739087795b2e3ed2be646e2f639"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}