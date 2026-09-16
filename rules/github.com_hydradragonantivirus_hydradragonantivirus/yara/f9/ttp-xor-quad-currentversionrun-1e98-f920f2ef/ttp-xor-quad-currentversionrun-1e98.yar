rule TTP_XOR_QUAD_CurrentVersionRun_1e98 {
  strings:
    $key_1e98 = { 4d f7 [2] 69 f9 [2] 42 d5 [2] 6c f7 [2] 78 ec [2] 77 f6 [2] 69 eb [2] 6b ea [2] 70 ec [2] 6c eb [2] 70 c4 }

  condition:
    any of them
}