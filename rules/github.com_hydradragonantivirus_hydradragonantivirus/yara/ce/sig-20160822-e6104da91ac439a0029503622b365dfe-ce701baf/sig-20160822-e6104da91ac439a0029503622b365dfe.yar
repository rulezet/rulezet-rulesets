rule sig_20160822_e6104da91ac439a0029503622b365dfe {
  meta:
    description = "datamaliciousorder - file 20160822_e6104da91ac439a0029503622b365dfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b649daf14418988a51ce63b76f082b78d46e38b792aadc38433b3ac1e131439"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}