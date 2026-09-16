rule sig_20161024_398b050280022e53559a2aa30a7e6557 {
  meta:
    description = "datamaliciousorder - file 20161024_398b050280022e53559a2aa30a7e6557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6c064f6007d0c7b6a2c6b914fccfba208242ddc218c88a9e6f2e0509860e22"

  strings:
    $s1 = "} while (gz0++ < rh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}