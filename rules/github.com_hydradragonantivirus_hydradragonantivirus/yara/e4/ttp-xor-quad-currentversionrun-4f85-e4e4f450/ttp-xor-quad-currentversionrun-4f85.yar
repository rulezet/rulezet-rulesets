rule TTP_XOR_QUAD_CurrentVersionRun_4f85 {
  strings:
    $key_4f85 = { 1c ea [2] 38 e4 [2] 13 c8 [2] 3d ea [2] 29 f1 [2] 26 eb [2] 38 f6 [2] 3a f7 [2] 21 f1 [2] 3d f6 [2] 21 d9 }

  condition:
    any of them
}