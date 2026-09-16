rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_99220520e874_1120 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1  = "turn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(f" ascii
    $s2  = "IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(functio" ascii
    $s3  = "){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})" ascii
    $s4  = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck()" ascii
    $s5  = "){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})" ascii
    $s6  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx" ascii
    $s7  = "urn \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s8  = "o\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s9  = ";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii
    $s10 = "uck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo" ascii
    $s11 = "ction fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s12 = "(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii
    $s13 = "ck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx" ascii
    $s14 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function f" ascii
    $s15 = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s16 = "return \"Ai\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s17 = "uck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Py" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}