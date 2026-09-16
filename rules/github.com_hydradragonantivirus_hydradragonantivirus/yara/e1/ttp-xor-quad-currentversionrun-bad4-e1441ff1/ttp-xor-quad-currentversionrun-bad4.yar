rule TTP_XOR_QUAD_CurrentVersionRun_bad4 {
  strings:
    $key_bad4 = { e9 bb [2] cd b5 [2] e6 99 [2] c8 bb [2] dc a0 [2] d3 ba [2] cd a7 [2] cf a6 [2] d4 a0 [2] c8 a7 [2] d4 88 }

  condition:
    any of them
}