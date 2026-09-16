rule TTP_XOR_QUAD_CurrentVersionRun_0398 {
  strings:
    $key_0398 = { 50 f7 [2] 74 f9 [2] 5f d5 [2] 71 f7 [2] 65 ec [2] 6a f6 [2] 74 eb [2] 76 ea [2] 6d ec [2] 71 eb [2] 6d c4 }

  condition:
    any of them
}