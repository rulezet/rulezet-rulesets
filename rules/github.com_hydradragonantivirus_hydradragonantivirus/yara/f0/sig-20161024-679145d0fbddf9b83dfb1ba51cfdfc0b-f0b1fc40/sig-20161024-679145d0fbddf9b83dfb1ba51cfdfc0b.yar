rule sig_20161024_679145d0fbddf9b83dfb1ba51cfdfc0b {
  meta:
    description = "datamaliciousorder - file 20161024_679145d0fbddf9b83dfb1ba51cfdfc0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d4075538a6d9a26b41737489944c4a48d983ab2cbc97ce1a13290efd1065c25"

  strings:
    $s1 = "} while (pc++ < ka);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}