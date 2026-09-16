rule sig_20160526_80c64b99f876330ec7d081837f83b2d8 {
  meta:
    description = "datamaliciousorder - file 20160526_80c64b99f876330ec7d081837f83b2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ce06599fb9cf096dc944ed78694e5b2c86483537d1ed41fc6b52f5268aeb34b"

  strings:
    $s1 = "DALE rav\\n\\r;\"gnel\" = nKLDEFZ rav\\n\\r;\"ht\" = 5vUCLDSN rav\\n\\r;\"tgnel\" = 9sQXF rav\\n\\r;\"h\" = 5pYQFWGU rav\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}