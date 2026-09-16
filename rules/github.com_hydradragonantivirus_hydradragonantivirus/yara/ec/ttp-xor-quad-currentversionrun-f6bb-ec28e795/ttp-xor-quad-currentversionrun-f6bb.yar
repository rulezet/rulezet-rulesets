rule TTP_XOR_QUAD_CurrentVersionRun_f6bb {
  strings:
    $key_f6bb = { a5 d4 [2] 81 da [2] aa f6 [2] 84 d4 [2] 90 cf [2] 9f d5 [2] 81 c8 [2] 83 c9 [2] 98 cf [2] 84 c8 [2] 98 e7 }

  condition:
    any of them
}