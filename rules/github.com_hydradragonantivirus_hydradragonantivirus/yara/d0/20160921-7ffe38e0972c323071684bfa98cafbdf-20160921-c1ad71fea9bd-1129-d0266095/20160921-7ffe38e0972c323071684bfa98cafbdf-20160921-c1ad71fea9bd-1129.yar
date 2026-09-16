rule _20160921_7ffe38e0972c323071684bfa98cafbdf_20160921_c1ad71fea9bd_1129 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1  = "{return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s2  = "Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s3  = "tion f000(){return \"DNa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4  = " f000(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"N" ascii
    $s5  = "){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s6  = "nction f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s7  = "function f000(){return \"Sj\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Lo\";})(),(function f000(){ret" ascii
    $s8  = "p\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s9  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s10 = "function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){ret" ascii
    $s11 = "00(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg" ascii
    $s12 = "00(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx" ascii
    $s13 = "(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){r" ascii
    $s14 = "\"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(fun" ascii
    $s15 = "){return \"Do\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s16 = "\"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s17 = "n f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}