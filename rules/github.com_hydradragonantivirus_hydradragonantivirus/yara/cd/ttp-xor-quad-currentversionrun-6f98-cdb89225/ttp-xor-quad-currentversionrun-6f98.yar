rule TTP_XOR_QUAD_CurrentVersionRun_6f98 {
  strings:
    $key_6f98 = { 3c f7 [2] 18 f9 [2] 33 d5 [2] 1d f7 [2] 09 ec [2] 06 f6 [2] 18 eb [2] 1a ea [2] 01 ec [2] 1d eb [2] 01 c4 }

  condition:
    any of them
}