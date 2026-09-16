rule TTP_XOR_QUAD_CurrentVersionRun_73bb {
  strings:
    $key_73bb = { 20 d4 [2] 04 da [2] 2f f6 [2] 01 d4 [2] 15 cf [2] 1a d5 [2] 04 c8 [2] 06 c9 [2] 1d cf [2] 01 c8 [2] 1d e7 }

  condition:
    any of them
}