rule sig_20160823_628d470005ccc5256e278085e5df0b4f {
  meta:
    description = "datamaliciousorder - file 20160823_628d470005ccc5256e278085e5df0b4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1e58c0beafb4268c4e37790797b0ed1fd3a6c1e227a542737406f20909e8a7b"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}