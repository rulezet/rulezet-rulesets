rule TTP_XOR_QUAD_CurrentVersionRun_0b84 {
  strings:
    $key_0b84 = { 58 eb [2] 7c e5 [2] 57 c9 [2] 79 eb [2] 6d f0 [2] 62 ea [2] 7c f7 [2] 7e f6 [2] 65 f0 [2] 79 f7 [2] 65 d8 }

  condition:
    any of them
}