rule sig_20161024_a3bd8a153e8645931e35a83535e86e36 {
  meta:
    description = "datamaliciousorder - file 20161024_a3bd8a153e8645931e35a83535e86e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8ff368f02d451290d81d35d086e849ea4792ef8f299031fbb4f6e86956fac16"

  strings:
    $s1 = "} while (ua++ < ej);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}