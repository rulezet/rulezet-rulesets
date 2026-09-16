rule TTP_XOR_QUAD_CurrentVersionRun_fc9a {
  strings:
    $key_fc9a = { af f5 [2] 8b fb [2] a0 d7 [2] 8e f5 [2] 9a ee [2] 95 f4 [2] 8b e9 [2] 89 e8 [2] 92 ee [2] 8e e9 [2] 92 c6 }

  condition:
    any of them
}