rule TTP_XOR_QUAD_CurrentVersionRun_5c98 {
  strings:
    $key_5c98 = { 0f f7 [2] 2b f9 [2] 00 d5 [2] 2e f7 [2] 3a ec [2] 35 f6 [2] 2b eb [2] 29 ea [2] 32 ec [2] 2e eb [2] 32 c4 }

  condition:
    any of them
}