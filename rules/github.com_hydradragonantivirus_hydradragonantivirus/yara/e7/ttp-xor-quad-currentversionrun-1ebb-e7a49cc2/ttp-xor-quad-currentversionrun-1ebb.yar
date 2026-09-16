rule TTP_XOR_QUAD_CurrentVersionRun_1ebb {
  strings:
    $key_1ebb = { 4d d4 [2] 69 da [2] 42 f6 [2] 6c d4 [2] 78 cf [2] 77 d5 [2] 69 c8 [2] 6b c9 [2] 70 cf [2] 6c c8 [2] 70 e7 }

  condition:
    any of them
}