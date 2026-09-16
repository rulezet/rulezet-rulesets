rule sig_20161024_3419ffa94e06b30ea17475da31cddeaa {
  meta:
    description = "datamaliciousorder - file 20161024_3419ffa94e06b30ea17475da31cddeaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97c40ac354286b8b2ae8eb22003c346451282557310bf38cb70245a67b318fc1"

  strings:
    $s1 = "} while (pv0++ < uw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}