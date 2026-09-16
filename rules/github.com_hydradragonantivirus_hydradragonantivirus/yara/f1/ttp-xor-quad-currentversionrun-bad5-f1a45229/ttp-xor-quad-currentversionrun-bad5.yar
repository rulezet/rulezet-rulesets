rule TTP_XOR_QUAD_CurrentVersionRun_bad5 {
  strings:
    $key_bad5 = { e9 ba [2] cd b4 [2] e6 98 [2] c8 ba [2] dc a1 [2] d3 bb [2] cd a6 [2] cf a7 [2] d4 a1 [2] c8 a6 [2] d4 89 }

  condition:
    any of them
}