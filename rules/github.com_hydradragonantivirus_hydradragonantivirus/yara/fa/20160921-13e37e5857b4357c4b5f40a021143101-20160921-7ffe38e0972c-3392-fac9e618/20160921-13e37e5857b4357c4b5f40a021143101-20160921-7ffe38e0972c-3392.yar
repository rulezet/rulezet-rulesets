rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_7ffe38e0972c_3392 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s2 = "nction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){retur" ascii
    $s3 = "tion f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s4 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})" ascii
    $s5 = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s6 = "urn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TKl\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}