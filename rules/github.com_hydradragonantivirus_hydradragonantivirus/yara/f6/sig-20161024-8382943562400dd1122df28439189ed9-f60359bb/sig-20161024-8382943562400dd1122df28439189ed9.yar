rule sig_20161024_8382943562400dd1122df28439189ed9 {
  meta:
    description = "datamaliciousorder - file 20161024_8382943562400dd1122df28439189ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d9219749096fb80339b1aba30aadb27e55558b4f9da8d481372bdd252f25c23"

  strings:
    $s1 = "} while (ii++ < me);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}