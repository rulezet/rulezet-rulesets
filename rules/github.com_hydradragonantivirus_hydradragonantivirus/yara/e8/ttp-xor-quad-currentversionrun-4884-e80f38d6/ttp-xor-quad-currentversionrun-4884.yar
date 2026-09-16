rule TTP_XOR_QUAD_CurrentVersionRun_4884 {
  strings:
    $key_4884 = { 1b eb [2] 3f e5 [2] 14 c9 [2] 3a eb [2] 2e f0 [2] 21 ea [2] 3f f7 [2] 3d f6 [2] 26 f0 [2] 3a f7 [2] 26 d8 }

  condition:
    any of them
}