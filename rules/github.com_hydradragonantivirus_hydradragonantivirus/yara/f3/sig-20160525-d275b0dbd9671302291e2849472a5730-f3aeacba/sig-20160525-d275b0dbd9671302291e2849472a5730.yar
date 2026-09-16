rule sig_20160525_d275b0dbd9671302291e2849472a5730 {
  meta:
    description = "datamaliciousorder - file 20160525_d275b0dbd9671302291e2849472a5730.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a610bd0acee807cbbefc612e46e8442f0726bf87af58b7e7e6fa27702ecca90b"

  strings:
    $s1 = "b[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- = deerda rav\\n;2 = tsilslianbmuhtoa rav\\n;1 = deerd rav\\n\\n;2037 - 5248" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}