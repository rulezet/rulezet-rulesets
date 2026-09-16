rule sig_20160822_8e02dd2feeab68ff0a0b2544a0af3663 {
  meta:
    description = "datamaliciousorder - file 20160822_8e02dd2feeab68ff0a0b2544a0af3663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3651e5c8bedcbea7e400492bdb20fc8ce8d5f1aa10cc86ab74374709ed2dd"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}