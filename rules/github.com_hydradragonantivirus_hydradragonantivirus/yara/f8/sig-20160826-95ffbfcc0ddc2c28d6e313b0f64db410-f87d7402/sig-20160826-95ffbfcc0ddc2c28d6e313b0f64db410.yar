rule sig_20160826_95ffbfcc0ddc2c28d6e313b0f64db410 {
  meta:
    description = "datamaliciousorder - file 20160826_95ffbfcc0ddc2c28d6e313b0f64db410.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c73871e53ffbf6a0ba2c9ef499b3bac3303a9632de6464ac41730e7c9eb1bd33"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4b\",\"\\x6e\",\"\\x3d\",\"\\x22\",\"\\x63\",\"\\x6c" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}