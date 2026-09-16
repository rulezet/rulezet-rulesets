rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_4d79e96b422e_714 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_4d79e96b422e6679059a17d9524e032c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "d5794a16a28dba8e89768fa9195da33a7e28c3da5fc73a7789e7c04395f23f06"

  strings:
    $s1  = "tion fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2  = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii
    $s3  = "eturn \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s4  = " fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"C" ascii
    $s5  = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function f" ascii
    $s6  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ot" ascii
    $s7  = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuc" ascii
    $s8  = ")(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s9  = "(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";}" ascii
    $s10 = "k(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";}" ascii
    $s11 = "on fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"" ascii
    $s12 = "(function fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){re" ascii
    $s13 = "{return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})" ascii
    $s14 = "(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s15 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"" ascii
    $s16 = "uck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu" ascii
    $s17 = "ck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\"" ascii
    $s18 = "{return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})" ascii
    $s19 = "ction fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return" ascii
    $s20 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Fv" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}