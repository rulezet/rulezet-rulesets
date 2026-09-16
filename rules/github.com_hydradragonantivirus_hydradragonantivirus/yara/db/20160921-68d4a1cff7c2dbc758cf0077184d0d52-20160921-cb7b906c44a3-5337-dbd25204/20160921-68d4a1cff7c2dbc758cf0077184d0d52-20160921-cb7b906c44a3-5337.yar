rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160921_cb7b906c44a3_5337 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = " \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s2 = "on f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s3 = "f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg" ascii
    $s4 = "function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){ret" ascii
    $s5 = "y\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}