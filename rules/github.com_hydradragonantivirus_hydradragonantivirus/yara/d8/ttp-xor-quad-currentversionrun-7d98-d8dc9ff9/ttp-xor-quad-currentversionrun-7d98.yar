rule TTP_XOR_QUAD_CurrentVersionRun_7d98 {
  strings:
    $key_7d98 = { 2e f7 [2] 0a f9 [2] 21 d5 [2] 0f f7 [2] 1b ec [2] 14 f6 [2] 0a eb [2] 08 ea [2] 13 ec [2] 0f eb [2] 13 c4 }

  condition:
    any of them
}