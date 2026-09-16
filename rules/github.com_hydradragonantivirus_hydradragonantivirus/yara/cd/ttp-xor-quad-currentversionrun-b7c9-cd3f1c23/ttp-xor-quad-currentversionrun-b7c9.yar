rule TTP_XOR_QUAD_CurrentVersionRun_b7c9 {
  strings:
    $key_b7c9 = { e4 a6 [2] c0 a8 [2] eb 84 [2] c5 a6 [2] d1 bd [2] de a7 [2] c0 ba [2] c2 bb [2] d9 bd [2] c5 ba [2] d9 95 }

  condition:
    any of them
}