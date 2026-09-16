rule sig_20160823_e70c223c22932429b53befd6400ef2e5 {
  meta:
    description = "datamaliciousorder - file 20160823_e70c223c22932429b53befd6400ef2e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c013c34636ccc6d4fc45e74ff62ca1b2145aa9c4459446b51f9b8ba7d7ca45c8"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}