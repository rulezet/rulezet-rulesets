rule TTP_XOR_QUAD_CurrentVersionRun_2e84 {
  strings:
    $key_2e84 = { 7d eb [2] 59 e5 [2] 72 c9 [2] 5c eb [2] 48 f0 [2] 47 ea [2] 59 f7 [2] 5b f6 [2] 40 f0 [2] 5c f7 [2] 40 d8 }

  condition:
    any of them
}