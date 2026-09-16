rule TTP_XOR_QUAD_CurrentVersionRun_7286 {
  strings:
    $key_7286 = { 21 e9 [2] 05 e7 [2] 2e cb [2] 00 e9 [2] 14 f2 [2] 1b e8 [2] 05 f5 [2] 07 f4 [2] 1c f2 [2] 00 f5 [2] 1c da }

  condition:
    any of them
}