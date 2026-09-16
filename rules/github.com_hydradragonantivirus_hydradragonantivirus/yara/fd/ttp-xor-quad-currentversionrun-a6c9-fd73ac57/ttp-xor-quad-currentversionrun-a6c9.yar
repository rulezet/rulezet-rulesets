rule TTP_XOR_QUAD_CurrentVersionRun_a6c9 {
  strings:
    $key_a6c9 = { f5 a6 [2] d1 a8 [2] fa 84 [2] d4 a6 [2] c0 bd [2] cf a7 [2] d1 ba [2] d3 bb [2] c8 bd [2] d4 ba [2] c8 95 }

  condition:
    any of them
}