rule TTP_XOR_QUAD_CurrentVersionRun_6598 {
  strings:
    $key_6598 = { 36 f7 [2] 12 f9 [2] 39 d5 [2] 17 f7 [2] 03 ec [2] 0c f6 [2] 12 eb [2] 10 ea [2] 0b ec [2] 17 eb [2] 0b c4 }

  condition:
    any of them
}