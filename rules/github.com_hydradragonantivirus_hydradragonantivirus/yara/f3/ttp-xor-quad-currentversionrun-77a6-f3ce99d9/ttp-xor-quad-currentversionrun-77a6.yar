rule TTP_XOR_QUAD_CurrentVersionRun_77a6 {
  strings:
    $key_77a6 = { 24 c9 [2] 00 c7 [2] 2b eb [2] 05 c9 [2] 11 d2 [2] 1e c8 [2] 00 d5 [2] 02 d4 [2] 19 d2 [2] 05 d5 [2] 19 fa }

  condition:
    any of them
}