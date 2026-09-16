rule sig_20160824_d4d380d9b50056494465af4d2f255a5c {
  meta:
    description = "datamaliciousorder - file 20160824_d4d380d9b50056494465af4d2f255a5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e00274ab6ce756eed165b53e1d9c2c8d6078665e0d8e8dc3098c5e4e2d631fb4"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}