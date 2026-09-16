rule TTP_XOR_QUAD_CurrentVersionRun_62a0 {
  strings:
    $key_62a0 = { 31 cf [2] 15 c1 [2] 3e ed [2] 10 cf [2] 04 d4 [2] 0b ce [2] 15 d3 [2] 17 d2 [2] 0c d4 [2] 10 d3 [2] 0c fc }

  condition:
    any of them
}