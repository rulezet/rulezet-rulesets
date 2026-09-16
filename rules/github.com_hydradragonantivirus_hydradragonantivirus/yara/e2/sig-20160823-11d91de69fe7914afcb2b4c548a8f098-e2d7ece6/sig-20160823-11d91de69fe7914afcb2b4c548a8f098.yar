rule sig_20160823_11d91de69fe7914afcb2b4c548a8f098 {
  meta:
    description = "datamaliciousorder - file 20160823_11d91de69fe7914afcb2b4c548a8f098.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6efa133c7d93bfbe6d3b704dd45406f8e5af32b2b6e5971d39b009d840b63d34"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}