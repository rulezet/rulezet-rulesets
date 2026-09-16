rule TTP_XOR_QUAD_CurrentVersionRun_7e98 {
  strings:
    $key_7e98 = { 2d f7 [2] 09 f9 [2] 22 d5 [2] 0c f7 [2] 18 ec [2] 17 f6 [2] 09 eb [2] 0b ea [2] 10 ec [2] 0c eb [2] 10 c4 }

  condition:
    any of them
}