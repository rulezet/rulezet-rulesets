rule sig_20161024_72b56447d6d84875137095ad61a7ad9f {
  meta:
    description = "datamaliciousorder - file 20161024_72b56447d6d84875137095ad61a7ad9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9653d9b7eca9e8af606b693d1d18f00ac6167d9523680acad363cfb9746bc54"

  strings:
    $s1 = "} while (jm++ < ac);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}