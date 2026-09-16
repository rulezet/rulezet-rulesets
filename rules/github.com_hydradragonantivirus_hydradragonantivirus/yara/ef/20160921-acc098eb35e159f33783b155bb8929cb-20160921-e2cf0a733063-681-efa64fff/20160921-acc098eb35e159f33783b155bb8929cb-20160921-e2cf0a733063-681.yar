rule _20160921_acc098eb35e159f33783b155bb8929cb_20160921_e2cf0a733063_681 {
  meta:
    description = "datamaliciousorder - from files 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash2       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1  = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s2  = "return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return " ascii
    $s4  = "MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s5  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck()" ascii
    $s6  = " \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s7  = "Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s8  = "n fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s9  = "\"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(funct" ascii
    $s10 = "u\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s11 = "k(){return \"Wo0\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\"" ascii
    $s12 = "(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";" ascii
    $s13 = "){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";}" ascii
    $s14 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii
    $s15 = "rn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s16 = "eturn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s17 = "\"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s18 = "ck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs" ascii
    $s19 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){retu" ascii
    $s20 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}