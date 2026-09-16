rule sig_20160823_5f2a0617fde1d11bb053a4b4ecbb7a6e {
  meta:
    description = "datamaliciousorder - file 20160823_5f2a0617fde1d11bb053a4b4ecbb7a6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed41354a4593501f677bf01566b05eb18d3c24cf2ad12fd0eb055b912039cbeb"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}