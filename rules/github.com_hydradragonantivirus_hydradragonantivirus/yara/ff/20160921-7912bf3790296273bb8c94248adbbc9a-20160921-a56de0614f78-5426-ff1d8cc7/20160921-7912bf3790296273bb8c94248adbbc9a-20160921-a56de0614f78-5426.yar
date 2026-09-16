rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_a56de0614f78_5426 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash3       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash4       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"
    hash5       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "eturn \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})()," ascii
    $s2 = "ction f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){retur" ascii
    $s3 = "n \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(func" ascii
    $s4 = "0(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";}" ascii
    $s5 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}