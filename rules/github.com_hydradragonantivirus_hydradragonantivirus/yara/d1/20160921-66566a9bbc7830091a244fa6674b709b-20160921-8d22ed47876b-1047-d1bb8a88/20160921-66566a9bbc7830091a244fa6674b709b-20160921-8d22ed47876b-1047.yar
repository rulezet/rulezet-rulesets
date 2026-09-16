rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_8d22ed47876b_1047 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash3       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1  = "0(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii
    $s2  = "(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";}" ascii
    $s3  = " \"Ot\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RVb\";})(),(funct" ascii
    $s4  = "000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s5  = "ion f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s6  = "n \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(fu" ascii
    $s7  = "(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){" ascii
    $s8  = "Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PLy\";})(),(functi" ascii
    $s9  = "{return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(" ascii
    $s10 = "on f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"M" ascii
    $s11 = "urn \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s12 = "(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s13 = "ction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){retu" ascii
    $s14 = "return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(" ascii
    $s15 = "){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";}" ascii
    $s16 = "})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000" ascii
    $s17 = "Pt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s18 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}