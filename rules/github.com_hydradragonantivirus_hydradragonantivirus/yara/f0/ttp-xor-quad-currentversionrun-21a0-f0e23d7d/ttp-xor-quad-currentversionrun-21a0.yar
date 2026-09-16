rule TTP_XOR_QUAD_CurrentVersionRun_21a0 {
  strings:
    $key_21a0 = { 72 cf [2] 56 c1 [2] 7d ed [2] 53 cf [2] 47 d4 [2] 48 ce [2] 56 d3 [2] 54 d2 [2] 4f d4 [2] 53 d3 [2] 4f fc }

  condition:
    any of them
}