rule TTP_XOR_QUAD_CurrentVersionRun_70a6 {
  strings:
    $key_70a6 = { 23 c9 [2] 07 c7 [2] 2c eb [2] 02 c9 [2] 16 d2 [2] 19 c8 [2] 07 d5 [2] 05 d4 [2] 1e d2 [2] 02 d5 [2] 1e fa }

  condition:
    any of them
}