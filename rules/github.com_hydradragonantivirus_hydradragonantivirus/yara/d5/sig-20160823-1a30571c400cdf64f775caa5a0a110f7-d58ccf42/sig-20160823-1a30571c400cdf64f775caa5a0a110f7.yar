rule sig_20160823_1a30571c400cdf64f775caa5a0a110f7 {
  meta:
    description = "datamaliciousorder - file 20160823_1a30571c400cdf64f775caa5a0a110f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f5162cd27ae61e5613798792a2e83692c74b3ee148dee7c2677cff1db7c2e2b"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}