rule TTP_XOR_QUAD_CurrentVersionRun_ea85 {
  strings:
    $key_ea85 = { b9 ea [2] 9d e4 [2] b6 c8 [2] 98 ea [2] 8c f1 [2] 83 eb [2] 9d f6 [2] 9f f7 [2] 84 f1 [2] 98 f6 [2] 84 d9 }

  condition:
    any of them
}