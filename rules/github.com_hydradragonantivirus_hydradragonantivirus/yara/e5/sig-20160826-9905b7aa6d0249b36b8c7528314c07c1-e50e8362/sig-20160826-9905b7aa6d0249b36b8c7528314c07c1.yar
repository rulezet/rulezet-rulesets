rule sig_20160826_9905b7aa6d0249b36b8c7528314c07c1 {
  meta:
    description = "datamaliciousorder - file 20160826_9905b7aa6d0249b36b8c7528314c07c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0de441c3f48eca48f72355b141e26738912c67679838f505ccef726d46d7403"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}