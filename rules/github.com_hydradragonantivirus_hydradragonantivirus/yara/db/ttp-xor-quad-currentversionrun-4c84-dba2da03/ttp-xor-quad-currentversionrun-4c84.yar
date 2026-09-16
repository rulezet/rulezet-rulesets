rule TTP_XOR_QUAD_CurrentVersionRun_4c84 {
  strings:
    $key_4c84 = { 1f eb [2] 3b e5 [2] 10 c9 [2] 3e eb [2] 2a f0 [2] 25 ea [2] 3b f7 [2] 39 f6 [2] 22 f0 [2] 3e f7 [2] 22 d8 }

  condition:
    any of them
}