rule TTP_XOR_QUAD_CurrentVersionRun_0f85 {
  strings:
    $key_0f85 = { 5c ea [2] 78 e4 [2] 53 c8 [2] 7d ea [2] 69 f1 [2] 66 eb [2] 78 f6 [2] 7a f7 [2] 61 f1 [2] 7d f6 [2] 61 d9 }

  condition:
    any of them
}