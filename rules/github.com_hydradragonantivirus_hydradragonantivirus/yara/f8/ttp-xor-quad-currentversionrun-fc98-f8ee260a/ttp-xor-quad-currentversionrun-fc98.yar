rule TTP_XOR_QUAD_CurrentVersionRun_fc98 {
  strings:
    $key_fc98 = { af f7 [2] 8b f9 [2] a0 d5 [2] 8e f7 [2] 9a ec [2] 95 f6 [2] 8b eb [2] 89 ea [2] 92 ec [2] 8e eb [2] 92 c4 }

  condition:
    any of them
}