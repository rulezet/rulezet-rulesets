rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_d6eab67b6b3c_5050 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "ion f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f" ascii
    $s3 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\"" ascii
    $s4 = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s5 = "Mz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}