rule sig_20161024_0870dcc84ead422ed91d8758972b46df {
  meta:
    description = "datamaliciousorder - file 20161024_0870dcc84ead422ed91d8758972b46df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63fe90a3e86df78875d9419a311498a7edf202b85c5bacd86bba2b337405cec3"

  strings:
    $s1 = "} while (nd++ < zh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}