rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_be882ab89423_1923 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1  = "){return \"DNa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(" ascii
    $s2  = "urn \"Yv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = "w\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function" ascii
    $s4  = "return \"KDh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5  = "0(){return \"Yv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";" ascii
    $s6  = "c\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s7  = "n \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s8  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s9  = "0(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc" ascii
    $s10 = " \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}