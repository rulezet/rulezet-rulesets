rule sig_20161024_7270ef832f89ed2469297e5804500f77 {
  meta:
    description = "datamaliciousorder - file 20161024_7270ef832f89ed2469297e5804500f77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a95aa811e30d0cbee043bbcdeb47556be5e3526c2262786856b35c1df5faba1"

  strings:
    $s1 = "} while (ac++ < zn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}