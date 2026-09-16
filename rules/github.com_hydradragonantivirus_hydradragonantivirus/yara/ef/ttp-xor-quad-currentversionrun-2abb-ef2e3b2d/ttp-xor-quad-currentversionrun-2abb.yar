rule TTP_XOR_QUAD_CurrentVersionRun_2abb {
  strings:
    $key_2abb = { 79 d4 [2] 5d da [2] 76 f6 [2] 58 d4 [2] 4c cf [2] 43 d5 [2] 5d c8 [2] 5f c9 [2] 44 cf [2] 58 c8 [2] 44 e7 }

  condition:
    any of them
}