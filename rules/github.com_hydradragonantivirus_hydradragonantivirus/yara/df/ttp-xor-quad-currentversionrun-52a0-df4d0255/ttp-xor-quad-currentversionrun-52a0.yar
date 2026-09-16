rule TTP_XOR_QUAD_CurrentVersionRun_52a0 {
  strings:
    $key_52a0 = { 01 cf [2] 25 c1 [2] 0e ed [2] 20 cf [2] 34 d4 [2] 3b ce [2] 25 d3 [2] 27 d2 [2] 3c d4 [2] 20 d3 [2] 3c fc }

  condition:
    any of them
}