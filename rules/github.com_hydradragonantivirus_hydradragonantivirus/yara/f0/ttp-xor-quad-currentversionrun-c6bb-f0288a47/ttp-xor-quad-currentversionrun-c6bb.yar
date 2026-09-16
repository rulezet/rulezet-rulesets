rule TTP_XOR_QUAD_CurrentVersionRun_c6bb {
  strings:
    $key_c6bb = { 95 d4 [2] b1 da [2] 9a f6 [2] b4 d4 [2] a0 cf [2] af d5 [2] b1 c8 [2] b3 c9 [2] a8 cf [2] b4 c8 [2] a8 e7 }

  condition:
    any of them
}