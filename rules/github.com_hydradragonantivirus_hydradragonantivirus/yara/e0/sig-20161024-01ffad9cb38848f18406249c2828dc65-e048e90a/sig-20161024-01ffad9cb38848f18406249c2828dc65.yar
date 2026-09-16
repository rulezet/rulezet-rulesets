rule sig_20161024_01ffad9cb38848f18406249c2828dc65 {
  meta:
    description = "datamaliciousorder - file 20161024_01ffad9cb38848f18406249c2828dc65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ddc6a3277b74c6ffb72ebd42cb23506b68f977b10fc5369708b55e77a0b3bc"

  strings:
    $s1 = "} while (oa++ < my);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}