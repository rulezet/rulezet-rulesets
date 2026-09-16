rule TTP_XOR_QUAD_CurrentVersionRun_61a0 {
  strings:
    $key_61a0 = { 32 cf [2] 16 c1 [2] 3d ed [2] 13 cf [2] 07 d4 [2] 08 ce [2] 16 d3 [2] 14 d2 [2] 0f d4 [2] 13 d3 [2] 0f fc }

  condition:
    any of them
}