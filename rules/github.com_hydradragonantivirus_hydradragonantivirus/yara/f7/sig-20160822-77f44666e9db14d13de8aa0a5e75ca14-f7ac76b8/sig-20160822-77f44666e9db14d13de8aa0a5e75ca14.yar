rule sig_20160822_77f44666e9db14d13de8aa0a5e75ca14 {
  meta:
    description = "datamaliciousorder - file 20160822_77f44666e9db14d13de8aa0a5e75ca14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1f13addd7f7a3da71d32c768cc100b2b22b7c0b968a8e43ab09ce13038094e8"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}