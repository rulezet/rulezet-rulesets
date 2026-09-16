rule sig_20161024_f0d456f997638dc764fafb342bf6c4b7 {
  meta:
    description = "datamaliciousorder - file 20161024_f0d456f997638dc764fafb342bf6c4b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f47b1fe744301215da8402a997b720e41278fd62c8b7e1619863655e83a589f"

  strings:
    $s1 = "} while (zl++ < zx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}