rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_9c9fcc818a70_5423 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"

  strings:
    $s1 = "){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa" ascii
    $s3 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx" ascii
    $s4 = "return \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5 = "n f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}