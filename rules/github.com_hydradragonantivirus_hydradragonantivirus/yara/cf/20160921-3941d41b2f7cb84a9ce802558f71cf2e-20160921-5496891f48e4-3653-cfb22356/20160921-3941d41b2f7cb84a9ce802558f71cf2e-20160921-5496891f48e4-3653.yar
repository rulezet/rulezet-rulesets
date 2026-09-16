rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_5496891f48e4_3653 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash3       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash4       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash5       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash6       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = "00(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";" ascii
    $s2 = "(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";" ascii
    $s3 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function " ascii
    $s4 = "nction f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = "return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s6 = "rn \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}