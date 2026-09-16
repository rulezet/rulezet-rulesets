rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_60c26fdfafa2_4878 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1 = "){return \"TKp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})" ascii
    $s2 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s3 = ",(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})(),(function f000(){re" ascii
    $s4 = "DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(functio" ascii
    $s5 = "unction f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}