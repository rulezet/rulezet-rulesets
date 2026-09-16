rule sig_20161024_dcf0fd58c24049dd3a234a200e0c6528 {
  meta:
    description = "datamaliciousorder - file 20161024_dcf0fd58c24049dd3a234a200e0c6528.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa2838c494b26f7271174e6c1f23e7def45d7938f2449302cd24095842554500"

  strings:
    $s1 = "} while (lx++ < zi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}