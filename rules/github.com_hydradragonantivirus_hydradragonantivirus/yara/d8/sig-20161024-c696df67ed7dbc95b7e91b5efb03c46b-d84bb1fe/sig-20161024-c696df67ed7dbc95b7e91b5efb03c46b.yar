rule sig_20161024_c696df67ed7dbc95b7e91b5efb03c46b {
  meta:
    description = "datamaliciousorder - file 20161024_c696df67ed7dbc95b7e91b5efb03c46b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "180ccd7545562b90f5e3cbcbaedca0920e3afc86b8a3a4499676609df235e8c6"

  strings:
    $s1 = "} while (bd++ < xq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}