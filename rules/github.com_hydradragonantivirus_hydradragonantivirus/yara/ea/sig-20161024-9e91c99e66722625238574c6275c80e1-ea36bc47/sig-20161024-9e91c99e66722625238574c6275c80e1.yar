rule sig_20161024_9e91c99e66722625238574c6275c80e1 {
  meta:
    description = "datamaliciousorder - file 20161024_9e91c99e66722625238574c6275c80e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1b6f48737689e60a18406b0fbdaefa79ed357ee98d64fb14ee3b5764b0df715"

  strings:
    $s1 = "} while (kd0++ < tm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}