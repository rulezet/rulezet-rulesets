rule sig_20161024_7a13aca31ab70f9d424c56992a392955 {
  meta:
    description = "datamaliciousorder - file 20161024_7a13aca31ab70f9d424c56992a392955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c3ccd6ee84b33c2574f8db7286690fdd385d4336ee51beb6de5e3e6af31bd7c"

  strings:
    $s1 = "} while (fx++ < xy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}