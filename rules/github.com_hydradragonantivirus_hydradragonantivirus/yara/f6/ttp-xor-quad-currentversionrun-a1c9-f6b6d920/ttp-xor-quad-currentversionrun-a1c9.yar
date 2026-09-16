rule TTP_XOR_QUAD_CurrentVersionRun_a1c9 {
  strings:
    $key_a1c9 = { f2 a6 [2] d6 a8 [2] fd 84 [2] d3 a6 [2] c7 bd [2] c8 a7 [2] d6 ba [2] d4 bb [2] cf bd [2] d3 ba [2] cf 95 }

  condition:
    any of them
}