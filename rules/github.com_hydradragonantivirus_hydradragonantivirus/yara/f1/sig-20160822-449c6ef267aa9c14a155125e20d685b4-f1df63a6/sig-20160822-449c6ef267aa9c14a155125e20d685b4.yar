rule sig_20160822_449c6ef267aa9c14a155125e20d685b4 {
  meta:
    description = "datamaliciousorder - file 20160822_449c6ef267aa9c14a155125e20d685b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89bd3c55a1d36131edf3343dd1c3a271d39666bd158ec4fe4ae7a73fa7fa19c2"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}