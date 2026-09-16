rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_4ad5ed78dc05_4649 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash3       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash4       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash5       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s2 = "on f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s3 = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s4 = "n \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(fu" ascii
    $s5 = "000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}