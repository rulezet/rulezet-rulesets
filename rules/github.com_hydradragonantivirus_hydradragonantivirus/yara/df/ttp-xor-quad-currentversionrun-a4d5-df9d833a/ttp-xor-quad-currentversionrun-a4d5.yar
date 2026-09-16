rule TTP_XOR_QUAD_CurrentVersionRun_a4d5 {
  strings:
    $key_a4d5 = { f7 ba [2] d3 b4 [2] f8 98 [2] d6 ba [2] c2 a1 [2] cd bb [2] d3 a6 [2] d1 a7 [2] ca a1 [2] d6 a6 [2] ca 89 }

  condition:
    any of them
}