rule TTP_XOR_QUAD_CurrentVersionRun_1385 {
  strings:
    $key_1385 = { 40 ea [2] 64 e4 [2] 4f c8 [2] 61 ea [2] 75 f1 [2] 7a eb [2] 64 f6 [2] 66 f7 [2] 7d f1 [2] 61 f6 [2] 7d d9 }

  condition:
    any of them
}