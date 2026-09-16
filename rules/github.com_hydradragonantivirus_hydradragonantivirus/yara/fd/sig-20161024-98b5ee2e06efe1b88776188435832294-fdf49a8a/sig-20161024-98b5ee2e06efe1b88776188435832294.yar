rule sig_20161024_98b5ee2e06efe1b88776188435832294 {
  meta:
    description = "datamaliciousorder - file 20161024_98b5ee2e06efe1b88776188435832294.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "012f1969e6a28c9100b4d4ea8d43e9fc6a48c6a3d4e3c52cb5e0def34dd27428"

  strings:
    $s1 = "} while (gv++ < mu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}