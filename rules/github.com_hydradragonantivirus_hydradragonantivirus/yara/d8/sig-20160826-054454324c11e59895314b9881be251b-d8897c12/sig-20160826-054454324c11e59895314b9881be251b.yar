rule sig_20160826_054454324c11e59895314b9881be251b {
  meta:
    description = "datamaliciousorder - file 20160826_054454324c11e59895314b9881be251b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b782f4db9383ba6f22131fff08ac491a7aa79008d817deefb3963e4bf808f8b"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}