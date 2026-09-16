rule sig_20161024_00bca0f81b922b147597a9974fe2eb82 {
  meta:
    description = "datamaliciousorder - file 20161024_00bca0f81b922b147597a9974fe2eb82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a445932214912883f98702db91ee53d01772f32e2d611a9d5173eba6f0317d6"

  strings:
    $s1 = "} while (ug++ < bq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}