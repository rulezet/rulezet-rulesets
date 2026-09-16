rule sig_20160823_27d7f37bf28857ca12420f4ad8477032 {
  meta:
    description = "datamaliciousorder - file 20160823_27d7f37bf28857ca12420f4ad8477032.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd78f69586174dcf3a1d0f02b39bb64e7e4c630118963b7d7f117bd134eeca4d"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}