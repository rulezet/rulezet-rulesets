rule TTP_XOR_QUAD_CurrentVersionRun_5085 {
  strings:
    $key_5085 = { 03 ea [2] 27 e4 [2] 0c c8 [2] 22 ea [2] 36 f1 [2] 39 eb [2] 27 f6 [2] 25 f7 [2] 3e f1 [2] 22 f6 [2] 3e d9 }

  condition:
    any of them
}