rule sig_20161024_8181a44d47f9b8f81b591288c46bbff1 {
  meta:
    description = "datamaliciousorder - file 20161024_8181a44d47f9b8f81b591288c46bbff1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "707c4ae80ea012a06a22994b624e995e7d4901a600c0eda2a9b15870aa408e1d"

  strings:
    $s1 = "} while (ku++ < hd0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}