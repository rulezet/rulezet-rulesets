rule TTP_XOR_QUAD_CurrentVersionRun_1287 {
  strings:
    $key_1287 = { 41 e8 [2] 65 e6 [2] 4e ca [2] 60 e8 [2] 74 f3 [2] 7b e9 [2] 65 f4 [2] 67 f5 [2] 7c f3 [2] 60 f4 [2] 7c db }

  condition:
    any of them
}