rule TTP_XOR_QUAD_CurrentVersionRun_3197 {
  strings:
    $key_3197 = { 62 f8 [2] 46 f6 [2] 6d da [2] 43 f8 [2] 57 e3 [2] 58 f9 [2] 46 e4 [2] 44 e5 [2] 5f e3 [2] 43 e4 [2] 5f cb }

  condition:
    any of them
}