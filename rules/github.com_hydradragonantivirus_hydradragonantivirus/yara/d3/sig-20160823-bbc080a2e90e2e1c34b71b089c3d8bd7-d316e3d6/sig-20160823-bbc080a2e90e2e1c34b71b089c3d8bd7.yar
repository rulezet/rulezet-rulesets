rule sig_20160823_bbc080a2e90e2e1c34b71b089c3d8bd7 {
  meta:
    description = "datamaliciousorder - file 20160823_bbc080a2e90e2e1c34b71b089c3d8bd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cfdd858375df93b3afd57aad1d74400f289d028211083a407b23e88103fc215"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}