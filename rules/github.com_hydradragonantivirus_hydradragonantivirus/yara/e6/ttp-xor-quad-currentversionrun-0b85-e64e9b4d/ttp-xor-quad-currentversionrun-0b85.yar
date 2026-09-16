rule TTP_XOR_QUAD_CurrentVersionRun_0b85 {
  strings:
    $key_0b85 = { 58 ea [2] 7c e4 [2] 57 c8 [2] 79 ea [2] 6d f1 [2] 62 eb [2] 7c f6 [2] 7e f7 [2] 65 f1 [2] 79 f6 [2] 65 d9 }

  condition:
    any of them
}