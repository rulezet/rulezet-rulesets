rule sig_20161024_17af89fa4ced81f4772c21c077599551 {
  meta:
    description = "datamaliciousorder - file 20161024_17af89fa4ced81f4772c21c077599551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a958d9eadabc73c8e8c455254efb5ffd6efd6c860305f7501be94b8ec017c5ec"

  strings:
    $s1 = "} while (af1++ < rj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}