rule _20160921_016aab466e10a29b831eb85b27664027_20160921_53ea150fd63a_4109 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash3       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash4       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1 = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})" ascii
    $s2 = "urn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s3 = "(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s4 = " f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"V" ascii
    $s5 = "OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}