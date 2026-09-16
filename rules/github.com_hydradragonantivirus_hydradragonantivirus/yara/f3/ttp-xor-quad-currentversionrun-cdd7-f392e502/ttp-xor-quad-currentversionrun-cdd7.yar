rule TTP_XOR_QUAD_CurrentVersionRun_cdd7 {
  strings:
    $key_cdd7 = { 9e b8 [2] ba b6 [2] 91 9a [2] bf b8 [2] ab a3 [2] a4 b9 [2] ba a4 [2] b8 a5 [2] a3 a3 [2] bf a4 [2] a3 8b }

  condition:
    any of them
}