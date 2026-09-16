rule TTP_XOR_QUAD_CurrentVersionRun_a486 {
  strings:
    $key_a486 = { f7 e9 [2] d3 e7 [2] f8 cb [2] d6 e9 [2] c2 f2 [2] cd e8 [2] d3 f5 [2] d1 f4 [2] ca f2 [2] d6 f5 [2] ca da }

  condition:
    any of them
}