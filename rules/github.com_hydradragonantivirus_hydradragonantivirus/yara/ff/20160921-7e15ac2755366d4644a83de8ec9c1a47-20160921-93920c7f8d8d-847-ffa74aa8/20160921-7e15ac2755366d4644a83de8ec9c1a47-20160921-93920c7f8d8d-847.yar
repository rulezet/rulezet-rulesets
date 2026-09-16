rule _20160921_7e15ac2755366d4644a83de8ec9c1a47_20160921_93920c7f8d8d_847 {
  meta:
    description = "datamaliciousorder - from files 20160921_7e15ac2755366d4644a83de8ec9c1a47.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1  = "function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2  = "on fuck(){return \"Ot\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s3  = "ck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj" ascii
    $s4  = "m\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function" ascii
    $s5  = "{return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";}" ascii
    $s6  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s7  = "{return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s8  = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s9  = "tion fuck(){return \"Ve\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return " ascii
    $s10 = "{return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})" ascii
    $s11 = "})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s12 = "rn \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s13 = "(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"OQr\";" ascii
    $s14 = "z\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"We\";})(),(function " ascii
    $s15 = "){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s16 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s17 = "function fuck(){return \"Qh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retu" ascii
    $s18 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s19 = "tion fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s20 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Pc\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}