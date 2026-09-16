rule sig_20161024_6407862510c3c60b3e7b7d25722615c7 {
  meta:
    description = "datamaliciousorder - file 20161024_6407862510c3c60b3e7b7d25722615c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa509c1693543268e9f39d5c0de6f5568931eba9ce4f757146a6ffca19fa5375"

  strings:
    $s1 = "} while (jp++ < ny0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}