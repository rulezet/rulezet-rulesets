rule sig_20160822_ee2742026bb898c21890e3668e2ac1e3 {
  meta:
    description = "datamaliciousorder - file 20160822_ee2742026bb898c21890e3668e2ac1e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37e9b6de9bdf204dd261b380d46a22dd6d57a76a66d8e5529a72350a8e5010cc"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}