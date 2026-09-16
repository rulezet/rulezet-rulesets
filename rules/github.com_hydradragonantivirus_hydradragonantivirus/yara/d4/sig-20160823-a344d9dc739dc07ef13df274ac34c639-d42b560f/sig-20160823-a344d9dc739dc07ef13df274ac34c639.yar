rule sig_20160823_a344d9dc739dc07ef13df274ac34c639 {
  meta:
    description = "datamaliciousorder - file 20160823_a344d9dc739dc07ef13df274ac34c639.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b05d84f95f99bc1ba42494d3fc8321d6c0b0b799f7dc3cc54e64909e424a895"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}