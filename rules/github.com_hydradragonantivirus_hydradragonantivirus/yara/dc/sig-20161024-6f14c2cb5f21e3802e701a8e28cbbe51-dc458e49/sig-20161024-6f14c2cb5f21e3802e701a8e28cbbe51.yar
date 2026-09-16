rule sig_20161024_6f14c2cb5f21e3802e701a8e28cbbe51 {
  meta:
    description = "datamaliciousorder - file 20161024_6f14c2cb5f21e3802e701a8e28cbbe51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abe8eadbc3618ff4f66aa17d2d9041614f4c53dd32b3499b977d3fb18f19e460"

  strings:
    $s1 = "} while (et++ < dv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}