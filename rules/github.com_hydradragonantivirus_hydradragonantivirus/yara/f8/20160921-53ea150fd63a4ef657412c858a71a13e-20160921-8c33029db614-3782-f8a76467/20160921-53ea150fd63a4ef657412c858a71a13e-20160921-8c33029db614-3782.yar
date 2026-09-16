rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_8c33029db614_3782 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash3       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"
    hash4       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "urn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s2 = ",(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s3 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){re" ascii
    $s4 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(" ascii
    $s5 = "){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})" ascii
    $s6 = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}