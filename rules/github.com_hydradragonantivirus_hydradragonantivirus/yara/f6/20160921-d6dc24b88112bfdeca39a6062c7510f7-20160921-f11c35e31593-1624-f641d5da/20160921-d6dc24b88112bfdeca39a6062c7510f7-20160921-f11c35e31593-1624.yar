rule _20160921_d6dc24b88112bfdeca39a6062c7510f7_20160921_f11c35e31593_1624 {
  meta:
    description = "datamaliciousorder - from files 20160921_d6dc24b88112bfdeca39a6062c7510f7.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1  = "{return \"Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(" ascii
    $s2  = "RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s3  = "eturn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()" ascii
    $s4  = ",(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RVb\";})(),(function f000(){r" ascii
    $s5  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"IAa\";})(),(function" ascii
    $s6  = "tion f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s7  = "),(function f000(){return \"Ot\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){" ascii
    $s8  = "\"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(functi" ascii
    $s9  = "ction f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s10 = "tion f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})" ascii
    $s12 = "n f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}