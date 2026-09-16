rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_da4ec6dae2ec_831 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1  = "n \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(fun" ascii
    $s2  = "00(){return \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj" ascii
    $s3  = "urn \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s4  = ")(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii
    $s5  = "){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GGn\";})" ascii
    $s6  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Go\";})(),(functi" ascii
    $s7  = "function f000(){return \"Vu\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s8  = "){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})" ascii
    $s9  = "eturn \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s10 = "f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s11 = "unction f000(){return \"ZGq\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s12 = "{return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(" ascii
    $s13 = "nction f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s14 = "unction f000(){return \"Go\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s15 = "\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"ZFe\";})(),(function " ascii
    $s16 = "eturn \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s17 = "Gn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(functi" ascii
    $s18 = "ion f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s19 = "00(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\"" ascii
    $s20 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}