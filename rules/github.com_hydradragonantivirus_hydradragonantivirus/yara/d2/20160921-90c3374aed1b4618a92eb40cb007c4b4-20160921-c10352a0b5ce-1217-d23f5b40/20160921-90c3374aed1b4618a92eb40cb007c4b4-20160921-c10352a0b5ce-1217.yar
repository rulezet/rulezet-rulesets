rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_c10352a0b5ce_1217 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1  = "{return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(" ascii
    $s2  = "ction f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3  = "n \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s4  = "00(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\"" ascii
    $s5  = "c\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(functio" ascii
    $s6  = "000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YT" ascii
    $s7  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f0" ascii
    $s8  = "000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg" ascii
    $s9  = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){ret" ascii
    $s10 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return" ascii
    $s11 = "(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii
    $s12 = "(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";}" ascii
    $s13 = "MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s14 = "unction f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})(),(function f000(){re" ascii
    $s15 = "ion f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return" ascii
    $s16 = "ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}