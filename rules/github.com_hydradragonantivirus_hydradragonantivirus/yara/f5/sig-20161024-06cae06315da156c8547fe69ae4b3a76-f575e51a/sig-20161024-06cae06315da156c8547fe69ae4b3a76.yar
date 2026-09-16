rule sig_20161024_06cae06315da156c8547fe69ae4b3a76 {
  meta:
    description = "datamaliciousorder - file 20161024_06cae06315da156c8547fe69ae4b3a76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3894e501364e4d173e22d63a56af518cc85ebae5d6853b17b10d1cc7598e3ec"

  strings:
    $s1 = "} while (id++ < jh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}