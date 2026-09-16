rule TTP_XOR_QUAD_CurrentVersionRun_a1d5 {
  strings:
    $key_a1d5 = { f2 ba [2] d6 b4 [2] fd 98 [2] d3 ba [2] c7 a1 [2] c8 bb [2] d6 a6 [2] d4 a7 [2] cf a1 [2] d3 a6 [2] cf 89 }

  condition:
    any of them
}