rule _20160921_02b826231ece268e91633311d2c70554_20160921_42c93aee0243_3184 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_42c93aee0243f217ab1a00a402ced889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"

  strings:
    $s1 = "000(){return \"Oe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj" ascii
    $s2 = "turn \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})()," ascii
    $s3 = "(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){re" ascii
    $s4 = "unction f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s5 = "unction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii
    $s6 = "Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}