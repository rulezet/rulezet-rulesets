rule sig_20160826_c269f5d6f3e72d31a6d978c0d6d9ba97 {
  meta:
    description = "datamaliciousorder - file 20160826_c269f5d6f3e72d31a6d978c0d6d9ba97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525126968896042bb7b7b5fa5d028ecf5c30b8cf4d474460a5cfa69965be7a8f"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}