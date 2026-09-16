rule TTP_XOR_QUAD_CurrentVersionRun_1f84 {
  strings:
    $key_1f84 = { 4c eb [2] 68 e5 [2] 43 c9 [2] 6d eb [2] 79 f0 [2] 76 ea [2] 68 f7 [2] 6a f6 [2] 71 f0 [2] 6d f7 [2] 71 d8 }

  condition:
    any of them
}