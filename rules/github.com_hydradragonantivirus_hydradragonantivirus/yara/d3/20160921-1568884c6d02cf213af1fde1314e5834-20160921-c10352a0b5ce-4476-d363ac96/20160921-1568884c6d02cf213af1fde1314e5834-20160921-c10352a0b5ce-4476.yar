rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_c10352a0b5ce_4476 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = " \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s4 = "n f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"K" ascii
    $s5 = " f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}