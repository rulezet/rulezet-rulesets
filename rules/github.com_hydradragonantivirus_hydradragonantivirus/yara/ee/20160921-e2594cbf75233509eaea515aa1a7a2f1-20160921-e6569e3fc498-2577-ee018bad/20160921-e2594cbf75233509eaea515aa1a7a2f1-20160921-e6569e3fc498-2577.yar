rule _20160921_e2594cbf75233509eaea515aa1a7a2f1_20160921_e6569e3fc498_2577 {
  meta:
    description = "datamaliciousorder - from files 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash2       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "00(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RVb" ascii
    $s2 = ",(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s3 = "0(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\"" ascii
    $s4 = "Vb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(functio" ascii
    $s5 = " \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s6 = "nction f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){retur" ascii
    $s7 = "})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s8 = "return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}