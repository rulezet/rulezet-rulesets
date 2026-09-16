rule sig_20160823_1b45b30364549eb5ba79a0ce46a6ab1e {
  meta:
    description = "datamaliciousorder - file 20160823_1b45b30364549eb5ba79a0ce46a6ab1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84e41d5bc730640275e567362c4dcd5063b9804eba339e19f22e1dc5651b61cb"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}