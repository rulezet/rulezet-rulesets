rule sig_20160822_dd639dd10cd468ffe2b28d06585ec433 {
  meta:
    description = "datamaliciousorder - file 20160822_dd639dd10cd468ffe2b28d06585ec433.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "147d461ef0de6b94eaff2422a6a06d796c65b4d6eef465be56536f7aec83aa6d"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}