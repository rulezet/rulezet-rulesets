rule sig_20160823_4041152d688f6b39ed7fc3b4c866f9a6 {
  meta:
    description = "datamaliciousorder - file 20160823_4041152d688f6b39ed7fc3b4c866f9a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a7bb2bcb5779ae0edfca0b9ab00b7ce24511f11ecfd89bee1d929d0917bc7eb"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}