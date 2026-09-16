rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_9dad243650b7_2110 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_9dad243650b7872772e7037b467b5a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"

  strings:
    $s1 = "RVb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(functio" ascii
    $s2 = "ion f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s3 = " \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s4 = "tion f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s5 = "eturn \"SGs\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s6 = "n f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii
    $s7 = "return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(" ascii
    $s8 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s9 = "turn \"SEo\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}