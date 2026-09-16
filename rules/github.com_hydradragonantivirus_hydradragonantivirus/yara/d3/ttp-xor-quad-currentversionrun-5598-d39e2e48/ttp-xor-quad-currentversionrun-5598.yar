rule TTP_XOR_QUAD_CurrentVersionRun_5598 {
  strings:
    $key_5598 = { 06 f7 [2] 22 f9 [2] 09 d5 [2] 27 f7 [2] 33 ec [2] 3c f6 [2] 22 eb [2] 20 ea [2] 3b ec [2] 27 eb [2] 3b c4 }

  condition:
    any of them
}