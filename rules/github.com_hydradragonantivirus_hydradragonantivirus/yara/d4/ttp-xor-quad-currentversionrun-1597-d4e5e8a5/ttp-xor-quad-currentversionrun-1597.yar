rule TTP_XOR_QUAD_CurrentVersionRun_1597 {
  strings:
    $key_1597 = { 46 f8 [2] 62 f6 [2] 49 da [2] 67 f8 [2] 73 e3 [2] 7c f9 [2] 62 e4 [2] 60 e5 [2] 7b e3 [2] 67 e4 [2] 7b cb }

  condition:
    any of them
}