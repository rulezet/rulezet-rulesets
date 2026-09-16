rule TTP_XOR_QUAD_CurrentVersionRun_4b84 {
  strings:
    $key_4b84 = { 18 eb [2] 3c e5 [2] 17 c9 [2] 39 eb [2] 2d f0 [2] 22 ea [2] 3c f7 [2] 3e f6 [2] 25 f0 [2] 39 f7 [2] 25 d8 }

  condition:
    any of them
}