rule TTP_XOR_QUAD_CurrentVersionRun_b0c9 {
  strings:
    $key_b0c9 = { e3 a6 [2] c7 a8 [2] ec 84 [2] c2 a6 [2] d6 bd [2] d9 a7 [2] c7 ba [2] c5 bb [2] de bd [2] c2 ba [2] de 95 }

  condition:
    any of them
}