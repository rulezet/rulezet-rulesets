rule sig_20161024_022eb3e5f8a7ad0f3ff7c3932a38ba06 {
  meta:
    description = "datamaliciousorder - file 20161024_022eb3e5f8a7ad0f3ff7c3932a38ba06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b89955c9c941b584828fe19d1f20a621fe8fbc3e3e3927d3cffd5a41abe60e77"

  strings:
    $s1 = "} while (jm0++ < ac);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}