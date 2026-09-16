rule TTP_XOR_QUAD_CurrentVersionRun_7998 {
  strings:
    $key_7998 = { 2a f7 [2] 0e f9 [2] 25 d5 [2] 0b f7 [2] 1f ec [2] 10 f6 [2] 0e eb [2] 0c ea [2] 17 ec [2] 0b eb [2] 17 c4 }

  condition:
    any of them
}