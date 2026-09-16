rule TTP_XOR_QUAD_CurrentVersionRun_2e98 {
  strings:
    $key_2e98 = { 7d f7 [2] 59 f9 [2] 72 d5 [2] 5c f7 [2] 48 ec [2] 47 f6 [2] 59 eb [2] 5b ea [2] 40 ec [2] 5c eb [2] 40 c4 }

  condition:
    any of them
}