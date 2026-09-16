rule TTP_XOR_QUAD_CurrentVersionRun_d183 {
  strings:
    $key_d183 = { 82 ec [2] a6 e2 [2] 8d ce [2] a3 ec [2] b7 f7 [2] b8 ed [2] a6 f0 [2] a4 f1 [2] bf f7 [2] a3 f0 [2] bf df }

  condition:
    any of them
}