rule TTP_XOR_QUAD_CurrentVersionRun_17a0 {
  strings:
    $key_17a0 = { 44 cf [2] 60 c1 [2] 4b ed [2] 65 cf [2] 71 d4 [2] 7e ce [2] 60 d3 [2] 62 d2 [2] 79 d4 [2] 65 d3 [2] 79 fc }

  condition:
    any of them
}