rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_8c8c9fad8af6_3048 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_8c8c9fad8af659443108d1078847a668.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"
    hash3       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "unction fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s2 = ";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s3 = "{return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(" ascii
    $s4 = " fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s5 = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s6 = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s7 = "ck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}