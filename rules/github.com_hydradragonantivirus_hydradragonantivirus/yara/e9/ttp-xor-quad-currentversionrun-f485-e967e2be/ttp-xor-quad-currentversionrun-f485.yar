rule TTP_XOR_QUAD_CurrentVersionRun_f485 {
  strings:
    $key_f485 = { a7 ea [2] 83 e4 [2] a8 c8 [2] 86 ea [2] 92 f1 [2] 9d eb [2] 83 f6 [2] 81 f7 [2] 9a f1 [2] 86 f6 [2] 9a d9 }

  condition:
    any of them
}