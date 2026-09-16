rule sig_20170429_878076717820bc0bd9900d74e3807a85 {
  meta:
    description = "datamaliciousorder - file 20170429_878076717820bc0bd9900d74e3807a85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4478b8dd68ec52eb9405deb4c55bd58ee893b609ffc3eef07afcf6a1a1288bed"

  strings:
    $s1 = "if (IQsvmuejicZpFTWXC() == false) {" fullword ascii
    $s2 = "function nQXjVOqkfSeDhPE(CORgkoNHKIdyfvUGVl, SkxYzLgbhlDjdwy, ElichjXpkCDGtHvOAa) { " fullword ascii
    $s3 = "return CORgkoNHKIdyfvUGVl.split(SkxYzLgbhlDjdwy).join(ElichjXpkCDGtHvOAa); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}