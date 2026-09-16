rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_53ea150fd63a_1337 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash4       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash5       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1  = "\"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s2  = " f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"R" ascii
    $s3  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq" ascii
    $s4  = "\"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s5  = "n f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s6  = "on f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){r" ascii
    $s8  = ";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f" ascii
    $s9  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f00" ascii
    $s10 = "rn \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s11 = "nction f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){retu" ascii
    $s12 = "return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})()" ascii
    $s13 = "ction f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s14 = "(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";" ascii
    $s15 = "ction f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}