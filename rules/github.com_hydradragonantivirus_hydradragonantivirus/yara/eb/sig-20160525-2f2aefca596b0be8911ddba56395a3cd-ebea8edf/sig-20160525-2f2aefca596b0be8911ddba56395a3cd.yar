rule sig_20160525_2f2aefca596b0be8911ddba56395a3cd {
  meta:
    description = "datamaliciousorder - file 20160525_2f2aefca596b0be8911ddba56395a3cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7912a6678befc6f56771cd9b5431f2c0ee7d5a7b84d732c0f094d2179690a2f"

  strings:
    $s1 = "b[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- = deerda rav\\n;2 = tsilslianbmuhtoa rav\\n;1 = deerd rav\\n\\n;2037 - 5248" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}