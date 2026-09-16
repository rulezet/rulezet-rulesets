rule TTP_XOR_QUAD_CurrentVersionRun_abc8 {
  strings:
    $key_abc8 = { f8 a7 [2] dc a9 [2] f7 85 [2] d9 a7 [2] cd bc [2] c2 a6 [2] dc bb [2] de ba [2] c5 bc [2] d9 bb [2] c5 94 }

  condition:
    any of them
}