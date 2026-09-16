rule TTP_XOR_QUAD_CurrentVersionRun_75a0 {
  strings:
    $key_75a0 = { 26 cf [2] 02 c1 [2] 29 ed [2] 07 cf [2] 13 d4 [2] 1c ce [2] 02 d3 [2] 00 d2 [2] 1b d4 [2] 07 d3 [2] 1b fc }

  condition:
    any of them
}