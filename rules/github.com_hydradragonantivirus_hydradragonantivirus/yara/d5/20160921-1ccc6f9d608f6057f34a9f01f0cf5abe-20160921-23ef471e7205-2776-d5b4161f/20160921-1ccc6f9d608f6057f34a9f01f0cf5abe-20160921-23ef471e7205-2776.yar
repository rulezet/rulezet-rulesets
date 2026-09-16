rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_23ef471e7205_2776 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash3       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1 = "(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\"" ascii
    $s2 = "unction f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4 = "n \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(func" ascii
    $s5 = "00(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"GGn" ascii
    $s6 = "turn \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(" ascii
    $s7 = " f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Q" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}