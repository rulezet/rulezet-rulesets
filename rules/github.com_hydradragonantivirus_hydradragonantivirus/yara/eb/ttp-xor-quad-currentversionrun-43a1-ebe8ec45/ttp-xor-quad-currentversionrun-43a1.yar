rule TTP_XOR_QUAD_CurrentVersionRun_43a1 {
  strings:
    $key_43a1 = { 10 ce [2] 34 c0 [2] 1f ec [2] 31 ce [2] 25 d5 [2] 2a cf [2] 34 d2 [2] 36 d3 [2] 2d d5 [2] 31 d2 [2] 2d fd }

  condition:
    any of them
}