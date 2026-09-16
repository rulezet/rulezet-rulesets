rule TTP_XOR_QUAD_CurrentVersionRun_f585 {
  strings:
    $key_f585 = { a6 ea [2] 82 e4 [2] a9 c8 [2] 87 ea [2] 93 f1 [2] 9c eb [2] 82 f6 [2] 80 f7 [2] 9b f1 [2] 87 f6 [2] 9b d9 }

  condition:
    any of them
}