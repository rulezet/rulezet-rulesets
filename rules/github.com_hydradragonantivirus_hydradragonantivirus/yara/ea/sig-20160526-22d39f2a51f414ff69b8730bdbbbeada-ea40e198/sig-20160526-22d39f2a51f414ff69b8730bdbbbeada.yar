rule sig_20160526_22d39f2a51f414ff69b8730bdbbbeada {
  meta:
    description = "datamaliciousorder - file 20160526_22d39f2a51f414ff69b8730bdbbbeada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01433ed0c036836f3d8adac3d5b163b1f7468617da2045071484bb07e5bc96c3"

  strings:
    $s1 = "k5tEOEMLO rav\\n;\"iFf6x\\\\45x\\\\\" = m1aRNGQPN rav\\n;\"ec6x\\\\\" = j6jNWBWFD rav\\n;\"e37x\\\\oc6x\\\\c\" = w9aJHPYTH rav'[" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}