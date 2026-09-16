rule sig_20161024_3335043a141cdf5e10111866e193ae31 {
  meta:
    description = "datamaliciousorder - file 20161024_3335043a141cdf5e10111866e193ae31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92687557b6b45542b1ec50d595df7d067fb6171e9871b2641992adad781ba4db"

  strings:
    $s1 = "} while (mz++ < ae0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}