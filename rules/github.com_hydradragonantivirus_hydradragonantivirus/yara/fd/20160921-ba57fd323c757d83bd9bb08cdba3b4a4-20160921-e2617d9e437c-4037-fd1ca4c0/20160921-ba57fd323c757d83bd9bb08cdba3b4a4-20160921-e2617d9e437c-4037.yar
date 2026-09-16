rule _20160921_ba57fd323c757d83bd9bb08cdba3b4a4_20160921_e2617d9e437c_4037 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash3       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1 = "on fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s2 = "return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})()" ascii
    $s3 = "(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){ret" ascii
    $s4 = "n \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5 = "g\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function " ascii
    $s6 = "(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}