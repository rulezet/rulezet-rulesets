rule sig_20161024_89a831616ee64d39376af9e380e16413 {
  meta:
    description = "datamaliciousorder - file 20161024_89a831616ee64d39376af9e380e16413.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf03da94064c7266e1bd51f539672cb8ee2496a34a525e622aed6fc4fe80746b"

  strings:
    $s1 = "} while (wv++ < hn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}