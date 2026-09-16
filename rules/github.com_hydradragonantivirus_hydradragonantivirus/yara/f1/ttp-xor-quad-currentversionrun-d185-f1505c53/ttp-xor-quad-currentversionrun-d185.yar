rule TTP_XOR_QUAD_CurrentVersionRun_d185 {
  strings:
    $key_d185 = { 82 ea [2] a6 e4 [2] 8d c8 [2] a3 ea [2] b7 f1 [2] b8 eb [2] a6 f6 [2] a4 f7 [2] bf f1 [2] a3 f6 [2] bf d9 }

  condition:
    any of them
}