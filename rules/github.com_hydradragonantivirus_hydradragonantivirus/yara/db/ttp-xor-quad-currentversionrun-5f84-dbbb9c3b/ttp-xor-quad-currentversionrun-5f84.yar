rule TTP_XOR_QUAD_CurrentVersionRun_5f84 {
  strings:
    $key_5f84 = { 0c eb [2] 28 e5 [2] 03 c9 [2] 2d eb [2] 39 f0 [2] 36 ea [2] 28 f7 [2] 2a f6 [2] 31 f0 [2] 2d f7 [2] 31 d8 }

  condition:
    any of them
}