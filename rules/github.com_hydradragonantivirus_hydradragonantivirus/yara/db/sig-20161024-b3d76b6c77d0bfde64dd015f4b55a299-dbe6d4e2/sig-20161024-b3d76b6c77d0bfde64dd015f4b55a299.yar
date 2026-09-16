rule sig_20161024_b3d76b6c77d0bfde64dd015f4b55a299 {
  meta:
    description = "datamaliciousorder - file 20161024_b3d76b6c77d0bfde64dd015f4b55a299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64718bc5ee1e6ae068d0133d609671ea6a5d602c6ad2bc19887703d17a5f85e4"

  strings:
    $s1 = "} while (sf++ < mx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}