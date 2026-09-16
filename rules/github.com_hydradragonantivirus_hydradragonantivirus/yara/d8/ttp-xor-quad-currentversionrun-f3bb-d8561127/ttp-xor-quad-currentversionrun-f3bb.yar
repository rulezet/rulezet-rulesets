rule TTP_XOR_QUAD_CurrentVersionRun_f3bb {
  strings:
    $key_f3bb = { a0 d4 [2] 84 da [2] af f6 [2] 81 d4 [2] 95 cf [2] 9a d5 [2] 84 c8 [2] 86 c9 [2] 9d cf [2] 81 c8 [2] 9d e7 }

  condition:
    any of them
}