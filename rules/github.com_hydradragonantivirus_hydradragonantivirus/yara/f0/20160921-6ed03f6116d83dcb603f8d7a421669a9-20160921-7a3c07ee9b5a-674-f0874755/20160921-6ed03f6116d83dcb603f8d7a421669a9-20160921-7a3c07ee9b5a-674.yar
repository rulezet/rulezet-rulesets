rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_7a3c07ee9b5a_674 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash3       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash4       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash5       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash6       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash7       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1  = "ion f000(){return \"Sj\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s2  = "\"Vu\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s3  = "ction f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s4  = "00(){return \"YTp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s5  = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})()," ascii
    $s6  = "f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s7  = "turn \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8  = "),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s9  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"RVb\";})(),(f" ascii
    $s10 = "eturn \"Um\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s11 = "000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s12 = "{return \"EZu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s13 = "on f000(){return \"HJm\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return " ascii
    $s14 = "00(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";" ascii
    $s15 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})()" ascii
    $s16 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTi\";" ascii
    $s17 = "return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(" ascii
    $s18 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){ret" ascii
    $s19 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"B" ascii
    $s20 = ";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}