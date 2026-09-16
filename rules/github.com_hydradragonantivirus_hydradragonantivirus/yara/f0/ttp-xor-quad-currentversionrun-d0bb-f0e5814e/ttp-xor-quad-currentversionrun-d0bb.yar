rule TTP_XOR_QUAD_CurrentVersionRun_d0bb {
  strings:
    $key_d0bb = { 83 d4 [2] a7 da [2] 8c f6 [2] a2 d4 [2] b6 cf [2] b9 d5 [2] a7 c8 [2] a5 c9 [2] be cf [2] a2 c8 [2] be e7 }

  condition:
    any of them
}