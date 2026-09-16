rule TTP_XOR_QUAD_CurrentVersionRun_26a0 {
  strings:
    $key_26a0 = { 75 cf [2] 51 c1 [2] 7a ed [2] 54 cf [2] 40 d4 [2] 4f ce [2] 51 d3 [2] 53 d2 [2] 48 d4 [2] 54 d3 [2] 48 fc }

  condition:
    any of them
}