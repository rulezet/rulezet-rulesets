rule sig_20161024_e96d4896bc74695a8f54f11255bde1bc {
  meta:
    description = "datamaliciousorder - file 20161024_e96d4896bc74695a8f54f11255bde1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2731d8a65351601d76c4570c165343bc9210e09278c8cedd4a7422267663e9e"

  strings:
    $s1 = "} while (ct++ < yk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}