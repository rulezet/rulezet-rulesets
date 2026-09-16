rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_7912bf379029_4548 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"

  strings:
    $s1 = "tion f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s2 = "(){return \"TKl\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s3 = "urn \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4 = "\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f" ascii
    $s5 = "nction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}