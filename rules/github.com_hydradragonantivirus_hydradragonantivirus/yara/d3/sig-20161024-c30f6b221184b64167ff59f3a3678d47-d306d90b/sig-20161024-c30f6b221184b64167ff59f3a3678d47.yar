rule sig_20161024_c30f6b221184b64167ff59f3a3678d47 {
  meta:
    description = "datamaliciousorder - file 20161024_c30f6b221184b64167ff59f3a3678d47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "393a4de7cb723642a65ea6aa7b475bcaadbebcc35efb181388ae0fa9ddeeaf90"

  strings:
    $s1 = "} while (os++ < yt0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}