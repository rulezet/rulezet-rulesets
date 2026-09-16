rule sig_20160516_77e9fa2f1d65fcf7513a9462e8cf3174 {
  meta:
    description = "datamaliciousorder - file 20160516_77e9fa2f1d65fcf7513a9462e8cf3174.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ced79d3b1ff461b060d121ac3b391503e18e39e74bc21d7738f5f867c17ca356"

  strings:
    $s1 = "var nza='vpwkdqavjxvyrer3f1 kgpnbknjmmnnjcbor4hgnvnkzj1bewb113fmwdqqvyw4eipgpyv2n2nixbdpzkrmq=zmq1o\\'s2wpstmlv1xckwvgynqygg4ihw" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}