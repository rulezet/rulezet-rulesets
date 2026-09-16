rule TTP_XOR_QUAD_CurrentVersionRun_4ebb {
  strings:
    $key_4ebb = { 1d d4 [2] 39 da [2] 12 f6 [2] 3c d4 [2] 28 cf [2] 27 d5 [2] 39 c8 [2] 3b c9 [2] 20 cf [2] 3c c8 [2] 20 e7 }

  condition:
    any of them
}