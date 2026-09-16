rule sig_20161024_43ed6a4ee481e6001de28d3cdaf77ded {
  meta:
    description = "datamaliciousorder - file 20161024_43ed6a4ee481e6001de28d3cdaf77ded.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6614ae88ae233f8f12f5e95101ed7c7b271b0d57d1a4f1af0271de1e7beccd0"

  strings:
    $s1 = "} while (au++ < wq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}