rule sig_20160823_6d86dcf9cdef76110e97f10cd5f9191e {
  meta:
    description = "datamaliciousorder - file 20160823_6d86dcf9cdef76110e97f10cd5f9191e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6097de8bab1e855851a5cdb09e3836c907a5d39ecf7db0938ad4cdc67b25715e"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}