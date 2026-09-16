rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_c10352a0b5ce_5509 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "t\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s2 = "(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s3 = "n \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s4 = "n \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}