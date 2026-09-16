rule TTP_XOR_QUAD_CurrentVersionRun_a4d1 {
  strings:
    $key_a4d1 = { f7 be [2] d3 b0 [2] f8 9c [2] d6 be [2] c2 a5 [2] cd bf [2] d3 a2 [2] d1 a3 [2] ca a5 [2] d6 a2 [2] ca 8d }

  condition:
    any of them
}