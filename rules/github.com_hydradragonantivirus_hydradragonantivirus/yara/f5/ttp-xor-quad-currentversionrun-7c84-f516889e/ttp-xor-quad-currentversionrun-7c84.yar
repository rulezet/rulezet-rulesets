rule TTP_XOR_QUAD_CurrentVersionRun_7c84 {
  strings:
    $key_7c84 = { 2f eb [2] 0b e5 [2] 20 c9 [2] 0e eb [2] 1a f0 [2] 15 ea [2] 0b f7 [2] 09 f6 [2] 12 f0 [2] 0e f7 [2] 12 d8 }

  condition:
    any of them
}