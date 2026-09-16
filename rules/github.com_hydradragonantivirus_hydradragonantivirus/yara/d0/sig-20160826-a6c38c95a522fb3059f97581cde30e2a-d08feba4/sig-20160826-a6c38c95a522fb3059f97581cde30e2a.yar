rule sig_20160826_a6c38c95a522fb3059f97581cde30e2a {
  meta:
    description = "datamaliciousorder - file 20160826_a6c38c95a522fb3059f97581cde30e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2be19ea6e052233bc49934080bbeb854318220f23b7be24054c5ec6e657eab2b"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}