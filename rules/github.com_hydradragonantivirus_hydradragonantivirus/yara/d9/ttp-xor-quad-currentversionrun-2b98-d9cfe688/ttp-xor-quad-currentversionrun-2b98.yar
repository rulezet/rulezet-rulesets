rule TTP_XOR_QUAD_CurrentVersionRun_2b98 {
  strings:
    $key_2b98 = { 78 f7 [2] 5c f9 [2] 77 d5 [2] 59 f7 [2] 4d ec [2] 42 f6 [2] 5c eb [2] 5e ea [2] 45 ec [2] 59 eb [2] 45 c4 }

  condition:
    any of them
}