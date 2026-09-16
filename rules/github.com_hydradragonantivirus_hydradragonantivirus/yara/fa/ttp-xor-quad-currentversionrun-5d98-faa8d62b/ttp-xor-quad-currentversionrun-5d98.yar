rule TTP_XOR_QUAD_CurrentVersionRun_5d98 {
  strings:
    $key_5d98 = { 0e f7 [2] 2a f9 [2] 01 d5 [2] 2f f7 [2] 3b ec [2] 34 f6 [2] 2a eb [2] 28 ea [2] 33 ec [2] 2f eb [2] 33 c4 }

  condition:
    any of them
}