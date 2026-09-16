rule sig_20160826_ab509d212782f608432d4b6ecbd863b4 {
  meta:
    description = "datamaliciousorder - file 20160826_ab509d212782f608432d4b6ecbd863b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e48fb4e597c32a88aa9bd9cc49e410683d977bf3751ddb719130f4ab018d20"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}