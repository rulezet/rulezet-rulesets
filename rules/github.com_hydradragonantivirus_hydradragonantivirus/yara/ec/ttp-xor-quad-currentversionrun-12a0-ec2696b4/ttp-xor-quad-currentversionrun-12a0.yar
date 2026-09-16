rule TTP_XOR_QUAD_CurrentVersionRun_12a0 {
  strings:
    $key_12a0 = { 41 cf [2] 65 c1 [2] 4e ed [2] 60 cf [2] 74 d4 [2] 7b ce [2] 65 d3 [2] 67 d2 [2] 7c d4 [2] 60 d3 [2] 7c fc }

  condition:
    any of them
}