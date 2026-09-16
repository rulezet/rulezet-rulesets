rule TTP_XOR_QUAD_CurrentVersionRun_6b98 {
  strings:
    $key_6b98 = { 38 f7 [2] 1c f9 [2] 37 d5 [2] 19 f7 [2] 0d ec [2] 02 f6 [2] 1c eb [2] 1e ea [2] 05 ec [2] 19 eb [2] 05 c4 }

  condition:
    any of them
}