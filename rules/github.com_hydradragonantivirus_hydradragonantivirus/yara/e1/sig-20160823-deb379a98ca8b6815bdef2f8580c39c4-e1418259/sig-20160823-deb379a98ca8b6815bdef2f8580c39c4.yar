rule sig_20160823_deb379a98ca8b6815bdef2f8580c39c4 {
  meta:
    description = "datamaliciousorder - file 20160823_deb379a98ca8b6815bdef2f8580c39c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fda9c2aa96359d32f39b10ee4fad9a67748b186a3a779d38e2c4477bc3931997"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}