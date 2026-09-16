rule sig_20161024_bb29854fa8cf2affbdc9d9aca2fa7e1a {
  meta:
    description = "datamaliciousorder - file 20161024_bb29854fa8cf2affbdc9d9aca2fa7e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80fe48a77a078dfb84266f081d1a10f78cca37daf7e9c41b915df8217a92082f"

  strings:
    $s1 = "} while (cy++ < xj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}