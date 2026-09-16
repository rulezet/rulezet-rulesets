rule sig_20161024_bb841810c6e9a029e5f2cbcfb4aeff87 {
  meta:
    description = "datamaliciousorder - file 20161024_bb841810c6e9a029e5f2cbcfb4aeff87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c00d4b1e1d5077c0152452a143d5b45b37652609f2e07cc08d8f38805a971c8e"

  strings:
    $s1 = "} while (eq++ < gq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}