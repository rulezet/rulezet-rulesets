rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_a65ac281dbfd_3360 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"

  strings:
    $s1 = "rn \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s2 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s3 = "return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})()," ascii
    $s4 = "urn \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s5 = "\"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(functi" ascii
    $s6 = "){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}