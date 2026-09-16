rule sig_20151203_baa438922684f7795d847b753d1dfa0a {
  meta:
    description = "datamaliciousorder - file 20151203_baa438922684f7795d847b753d1dfa0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7ee4be1ef81144f07e9bb4884f34ce8456aaaa1bec900f63b63864fed7c61a3"

  strings:
    $s1 = "Gi[3]);return cBbKsaFQlIorZdnqCxd}" fullword ascii
    $s2 = "function j(yizVRYyaGi){ cBbKsaFQlIorZdnqCxd='';for(XwfmpWAlWWPmimxaawsuG = 0; XwfmpWAlWWPmimxaawsuG < 3; XwfmpWAlWWPmimxaawsuG++" ascii
    $s3 = "function j(yizVRYyaGi){ cBbKsaFQlIorZdnqCxd='';for(XwfmpWAlWWPmimxaawsuG = 0; XwfmpWAlWWPmimxaawsuG < 3; XwfmpWAlWWPmimxaawsuG++" ascii
    $s4 = "function VzzMcaGMoLDZiwDCIxJUToTFlxEIDgIxE(UvBecVMaBJKDrmmZdWzMR){eval(UvBecVMaBJKDrmmZdWzMR)};" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}