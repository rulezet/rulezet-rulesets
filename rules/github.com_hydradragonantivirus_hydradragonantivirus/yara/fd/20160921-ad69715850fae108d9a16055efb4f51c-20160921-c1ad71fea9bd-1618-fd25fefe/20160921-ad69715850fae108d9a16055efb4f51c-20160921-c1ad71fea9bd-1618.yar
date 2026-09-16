rule _20160921_ad69715850fae108d9a16055efb4f51c_20160921_c1ad71fea9bd_1618 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad69715850fae108d9a16055efb4f51c.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1  = "b\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"TKl\";})(),(function" ascii
    $s2  = " \"RPt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(func" ascii
    $s3  = "turn \"IPu\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s4  = "0(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\"" ascii
    $s5  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s6  = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f00" ascii
    $s7  = "unction f000(){return \"PTi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s8  = " f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"S" ascii
    $s9  = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s10 = "b\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s11 = "{return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OMd\";}" ascii
    $s12 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"SEo\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}