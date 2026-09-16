rule TTP_XOR_QUAD_CurrentVersionRun_5c84 {
  strings:
    $key_5c84 = { 0f eb [2] 2b e5 [2] 00 c9 [2] 2e eb [2] 3a f0 [2] 35 ea [2] 2b f7 [2] 29 f6 [2] 32 f0 [2] 2e f7 [2] 32 d8 }

  condition:
    any of them
}