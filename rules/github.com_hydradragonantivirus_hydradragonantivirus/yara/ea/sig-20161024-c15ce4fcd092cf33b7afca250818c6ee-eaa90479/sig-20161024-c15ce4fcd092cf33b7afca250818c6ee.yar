rule sig_20161024_c15ce4fcd092cf33b7afca250818c6ee {
  meta:
    description = "datamaliciousorder - file 20161024_c15ce4fcd092cf33b7afca250818c6ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "809d96a5abab7f586a228cf459aadb0fee35dbc9be4a92dc4eef0d13c3971c2e"

  strings:
    $s1 = "} while (mp++ < gr0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}