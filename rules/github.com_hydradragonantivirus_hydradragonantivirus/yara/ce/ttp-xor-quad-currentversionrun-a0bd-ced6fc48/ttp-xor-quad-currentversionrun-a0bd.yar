rule TTP_XOR_QUAD_CurrentVersionRun_a0bd {
  strings:
    $key_a0bd = { f3 d2 [2] d7 dc [2] fc f0 [2] d2 d2 [2] c6 c9 [2] c9 d3 [2] d7 ce [2] d5 cf [2] ce c9 [2] d2 ce [2] ce e1 }

  condition:
    any of them
}