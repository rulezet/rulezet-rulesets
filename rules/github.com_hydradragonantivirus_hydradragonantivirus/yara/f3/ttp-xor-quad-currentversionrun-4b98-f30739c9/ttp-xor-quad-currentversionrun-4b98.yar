rule TTP_XOR_QUAD_CurrentVersionRun_4b98 {
  strings:
    $key_4b98 = { 18 f7 [2] 3c f9 [2] 17 d5 [2] 39 f7 [2] 2d ec [2] 22 f6 [2] 3c eb [2] 3e ea [2] 25 ec [2] 39 eb [2] 25 c4 }

  condition:
    any of them
}