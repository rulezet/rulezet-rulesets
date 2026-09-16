rule sig_20161024_f134bf1f3713aab2da205745948496f7 {
  meta:
    description = "datamaliciousorder - file 20161024_f134bf1f3713aab2da205745948496f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d2d72509f8db11cfba8f1e99f182d59bea0d97762b8b68d2275704b841d53ef"

  strings:
    $s1 = "} while (nx++ < os0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}