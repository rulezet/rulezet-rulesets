rule TTP_XOR_QUAD_CurrentVersionRun_ec84 {
  strings:
    $key_ec84 = { bf eb [2] 9b e5 [2] b0 c9 [2] 9e eb [2] 8a f0 [2] 85 ea [2] 9b f7 [2] 99 f6 [2] 82 f0 [2] 9e f7 [2] 82 d8 }

  condition:
    any of them
}