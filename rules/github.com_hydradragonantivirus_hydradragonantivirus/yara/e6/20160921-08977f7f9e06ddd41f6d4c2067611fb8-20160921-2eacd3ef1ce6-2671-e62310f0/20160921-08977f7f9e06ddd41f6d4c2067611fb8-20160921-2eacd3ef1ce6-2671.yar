rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_2eacd3ef1ce6_2671 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash4       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s2 = "(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = " \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\"" ascii
    $s5 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){ret" ascii
    $s6 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s7 = "(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}