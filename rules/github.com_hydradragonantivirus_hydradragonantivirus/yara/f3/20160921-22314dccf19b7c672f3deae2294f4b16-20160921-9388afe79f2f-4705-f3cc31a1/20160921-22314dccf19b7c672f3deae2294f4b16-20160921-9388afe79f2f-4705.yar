rule _20160921_22314dccf19b7c672f3deae2294f4b16_20160921_9388afe79f2f_4705 {
  meta:
    description = "datamaliciousorder - from files 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash2       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash3       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s2 = "){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})" ascii
    $s3 = " f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Z" ascii
    $s4 = " f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"L" ascii
    $s5 = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}