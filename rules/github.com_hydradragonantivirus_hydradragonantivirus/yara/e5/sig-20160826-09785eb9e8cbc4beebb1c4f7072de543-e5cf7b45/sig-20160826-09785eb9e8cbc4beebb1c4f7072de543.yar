rule sig_20160826_09785eb9e8cbc4beebb1c4f7072de543 {
  meta:
    description = "datamaliciousorder - file 20160826_09785eb9e8cbc4beebb1c4f7072de543.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b518b4c4edf2c916848db5435fa8147e13f8e2b169b2b39ea9bcc1d3fc66411c"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}