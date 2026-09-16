rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_d6dc24b88112_1740 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1  = "(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000" ascii
    $s2  = "on f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"" ascii
    $s3  = "urn \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s4  = "eturn \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5  = "i\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function " ascii
    $s6  = "urn \"Vj\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s7  = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})()" ascii
    $s8  = ";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(fun" ascii
    $s10 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(" ascii
    $s11 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"H" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}