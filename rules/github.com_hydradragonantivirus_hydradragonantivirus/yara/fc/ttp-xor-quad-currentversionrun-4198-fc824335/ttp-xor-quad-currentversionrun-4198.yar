rule TTP_XOR_QUAD_CurrentVersionRun_4198 {
  strings:
    $key_4198 = { 12 f7 [2] 36 f9 [2] 1d d5 [2] 33 f7 [2] 27 ec [2] 28 f6 [2] 36 eb [2] 34 ea [2] 2f ec [2] 33 eb [2] 2f c4 }

  condition:
    any of them
}