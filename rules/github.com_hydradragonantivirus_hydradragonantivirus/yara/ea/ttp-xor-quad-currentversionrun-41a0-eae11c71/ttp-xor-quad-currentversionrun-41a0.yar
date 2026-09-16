rule TTP_XOR_QUAD_CurrentVersionRun_41a0 {
  strings:
    $key_41a0 = { 12 cf [2] 36 c1 [2] 1d ed [2] 33 cf [2] 27 d4 [2] 28 ce [2] 36 d3 [2] 34 d2 [2] 2f d4 [2] 33 d3 [2] 2f fc }

  condition:
    any of them
}