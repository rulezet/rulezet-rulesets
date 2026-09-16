rule _20160921_76157564ae9f7ad7ec97100684b2a5ce_20160921_aa7387335b72_3914 {
  meta:
    description = "datamaliciousorder - from files 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash2       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1 = "{return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(" ascii
    $s2 = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s3 = "turn \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s4 = "turn \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s5 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"" ascii
    $s6 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}