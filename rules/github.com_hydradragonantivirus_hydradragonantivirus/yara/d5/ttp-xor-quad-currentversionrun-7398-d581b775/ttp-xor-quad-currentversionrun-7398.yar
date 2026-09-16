rule TTP_XOR_QUAD_CurrentVersionRun_7398 {
  strings:
    $key_7398 = { 20 f7 [2] 04 f9 [2] 2f d5 [2] 01 f7 [2] 15 ec [2] 1a f6 [2] 04 eb [2] 06 ea [2] 1d ec [2] 01 eb [2] 1d c4 }

  condition:
    any of them
}