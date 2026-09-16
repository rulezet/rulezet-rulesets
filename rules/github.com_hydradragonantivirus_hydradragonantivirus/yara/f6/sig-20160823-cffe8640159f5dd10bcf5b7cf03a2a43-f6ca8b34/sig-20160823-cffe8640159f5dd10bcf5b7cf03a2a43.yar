rule sig_20160823_cffe8640159f5dd10bcf5b7cf03a2a43 {
  meta:
    description = "datamaliciousorder - file 20160823_cffe8640159f5dd10bcf5b7cf03a2a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4898aa1e3555953b4f3a128581fe71035bbd98919bc015fdf50d99032fbb36e"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}