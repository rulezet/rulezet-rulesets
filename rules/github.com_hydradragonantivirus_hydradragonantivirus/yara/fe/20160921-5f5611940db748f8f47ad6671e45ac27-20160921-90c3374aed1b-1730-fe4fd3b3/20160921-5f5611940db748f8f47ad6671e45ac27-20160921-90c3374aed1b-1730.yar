rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_90c3374aed1b_1730 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash3       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"

  strings:
    $s1  = "Gq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s2  = "(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";" ascii
    $s3  = "){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"YTp\";}" ascii
    $s4  = "00(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = "000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BQb" ascii
    $s6  = "(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){re" ascii
    $s7  = "0(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\"" ascii
    $s8  = "Qb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s9  = "ction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s10 = "MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s11 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}