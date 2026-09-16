rule TTP_XOR_QUAD_CurrentVersionRun_ea84 {
  strings:
    $key_ea84 = { b9 eb [2] 9d e5 [2] b6 c9 [2] 98 eb [2] 8c f0 [2] 83 ea [2] 9d f7 [2] 9f f6 [2] 84 f0 [2] 98 f7 [2] 84 d8 }

  condition:
    any of them
}