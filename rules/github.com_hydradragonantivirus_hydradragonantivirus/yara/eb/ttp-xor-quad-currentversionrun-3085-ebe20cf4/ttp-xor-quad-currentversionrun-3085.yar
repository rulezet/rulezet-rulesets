rule TTP_XOR_QUAD_CurrentVersionRun_3085 {
  strings:
    $key_3085 = { 63 ea [2] 47 e4 [2] 6c c8 [2] 42 ea [2] 56 f1 [2] 59 eb [2] 47 f6 [2] 45 f7 [2] 5e f1 [2] 42 f6 [2] 5e d9 }

  condition:
    any of them
}