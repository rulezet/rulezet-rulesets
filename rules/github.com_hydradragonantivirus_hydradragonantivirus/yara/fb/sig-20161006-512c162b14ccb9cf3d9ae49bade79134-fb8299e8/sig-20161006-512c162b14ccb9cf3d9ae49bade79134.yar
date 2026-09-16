rule sig_20161006_512c162b14ccb9cf3d9ae49bade79134 {
  meta:
    description = "datamaliciousorder - file 20161006_512c162b14ccb9cf3d9ae49bade79134.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f685354ec6cc06f9279aaafd7ed8f90501997459109d6b32bdf87c9870720ff0"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}