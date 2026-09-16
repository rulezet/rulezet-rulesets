rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_d6dc24b88112_4472 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1 = "nction f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s2 = "00(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn" ascii
    $s3 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s4 = "Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(functio" ascii
    $s5 = "){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}