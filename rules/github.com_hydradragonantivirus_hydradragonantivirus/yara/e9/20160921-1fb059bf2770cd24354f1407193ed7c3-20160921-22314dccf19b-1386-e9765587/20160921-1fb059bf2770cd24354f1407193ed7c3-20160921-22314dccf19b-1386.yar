rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_22314dccf19b_1386 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sv" ascii
    $s2  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){ret" ascii
    $s3  = "on f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"" ascii
    $s4  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s5  = "{return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(" ascii
    $s6  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s7  = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})" ascii
    $s8  = "n f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"" ascii
    $s9  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s10 = "on f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii
    $s11 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZFe" ascii
    $s12 = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s13 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function f000(){r" ascii
    $s14 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}