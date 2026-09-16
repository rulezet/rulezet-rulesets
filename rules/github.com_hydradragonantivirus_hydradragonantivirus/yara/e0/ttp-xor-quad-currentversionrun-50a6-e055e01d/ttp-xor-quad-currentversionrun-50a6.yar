rule TTP_XOR_QUAD_CurrentVersionRun_50a6 {
  strings:
    $key_50a6 = { 03 c9 [2] 27 c7 [2] 0c eb [2] 22 c9 [2] 36 d2 [2] 39 c8 [2] 27 d5 [2] 25 d4 [2] 3e d2 [2] 22 d5 [2] 3e fa }

  condition:
    any of them
}