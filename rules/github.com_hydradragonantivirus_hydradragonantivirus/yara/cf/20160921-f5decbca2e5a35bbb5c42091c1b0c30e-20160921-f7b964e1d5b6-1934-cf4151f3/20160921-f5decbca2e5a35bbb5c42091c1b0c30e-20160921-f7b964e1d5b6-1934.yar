rule _20160921_f5decbca2e5a35bbb5c42091c1b0c30e_20160921_f7b964e1d5b6_1934 {
  meta:
    description = "datamaliciousorder - from files 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1  = "{return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})" ascii
    $s2  = "\"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s3  = "n \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s4  = " f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"M" ascii
    $s5  = "eturn \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s6  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})" ascii
    $s7  = "Db\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s8  = "000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn" ascii
    $s9  = "Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(functi" ascii
    $s10 = "ction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}