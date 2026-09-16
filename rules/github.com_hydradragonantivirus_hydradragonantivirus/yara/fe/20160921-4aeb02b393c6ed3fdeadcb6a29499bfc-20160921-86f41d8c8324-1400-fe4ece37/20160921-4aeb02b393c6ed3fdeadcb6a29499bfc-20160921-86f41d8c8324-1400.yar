rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160921_86f41d8c8324_1400 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash3       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash4       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1  = "000(){return \"Ml\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg" ascii
    $s2  = "ction f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return" ascii
    $s3  = "{return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(" ascii
    $s4  = ";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s5  = "000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj" ascii
    $s6  = "{return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})" ascii
    $s7  = "q\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function" ascii
    $s8  = "unction f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s9  = "function f000(){return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){re" ascii
    $s10 = "){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})" ascii
    $s11 = " f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZI" ascii
    $s12 = "})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s13 = "tion f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s14 = "n \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}