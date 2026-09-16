rule sig_20161024_457ac01880fd941c5eb0cb366bb8f7b4 {
  meta:
    description = "datamaliciousorder - file 20161024_457ac01880fd941c5eb0cb366bb8f7b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c3f35992f1a5ca007334b7cda86292a103482453dec00853bc1aabafe6ba55b"

  strings:
    $s1 = "} while (wn++ < ra0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}