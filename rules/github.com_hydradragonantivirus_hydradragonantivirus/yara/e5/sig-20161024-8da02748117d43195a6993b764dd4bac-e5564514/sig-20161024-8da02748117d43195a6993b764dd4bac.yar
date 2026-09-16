rule sig_20161024_8da02748117d43195a6993b764dd4bac {
  meta:
    description = "datamaliciousorder - file 20161024_8da02748117d43195a6993b764dd4bac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93ba73858c6753e915aae6a6a48a0a0b8a571206331a09905da8a11ed4f22e46"

  strings:
    $s1 = "} while (un++ < wd0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}