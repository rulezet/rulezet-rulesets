rule TTP_XOR_QUAD_CurrentVersionRun_a4b7 {
  strings:
    $key_a4b7 = { f7 d8 [2] d3 d6 [2] f8 fa [2] d6 d8 [2] c2 c3 [2] cd d9 [2] d3 c4 [2] d1 c5 [2] ca c3 [2] d6 c4 [2] ca eb }

  condition:
    any of them
}