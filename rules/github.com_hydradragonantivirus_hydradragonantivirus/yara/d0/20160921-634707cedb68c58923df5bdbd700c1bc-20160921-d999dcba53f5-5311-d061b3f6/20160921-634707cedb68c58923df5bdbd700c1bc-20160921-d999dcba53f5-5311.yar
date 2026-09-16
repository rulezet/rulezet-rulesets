rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_d999dcba53f5_5311 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = " \"ZIi\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s2 = "(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s3 = "n f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s4 = "){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s5 = "turn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}