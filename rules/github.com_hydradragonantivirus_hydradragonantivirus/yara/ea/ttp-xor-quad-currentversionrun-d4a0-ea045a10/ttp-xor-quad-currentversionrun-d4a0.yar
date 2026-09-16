rule TTP_XOR_QUAD_CurrentVersionRun_d4a0 {
  strings:
    $key_d4a0 = { 87 cf [2] a3 c1 [2] 88 ed [2] a6 cf [2] b2 d4 [2] bd ce [2] a3 d3 [2] a1 d2 [2] ba d4 [2] a6 d3 [2] ba fc }

  condition:
    any of them
}