rule TTP_XOR_QUAD_CurrentVersionRun_d2a0 {
  strings:
    $key_d2a0 = { 81 cf [2] a5 c1 [2] 8e ed [2] a0 cf [2] b4 d4 [2] bb ce [2] a5 d3 [2] a7 d2 [2] bc d4 [2] a0 d3 [2] bc fc }

  condition:
    any of them
}