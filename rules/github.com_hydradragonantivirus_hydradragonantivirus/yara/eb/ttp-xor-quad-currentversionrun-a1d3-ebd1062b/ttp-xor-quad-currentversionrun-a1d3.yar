rule TTP_XOR_QUAD_CurrentVersionRun_a1d3 {
  strings:
    $key_a1d3 = { f2 bc [2] d6 b2 [2] fd 9e [2] d3 bc [2] c7 a7 [2] c8 bd [2] d6 a0 [2] d4 a1 [2] cf a7 [2] d3 a0 [2] cf 8f }

  condition:
    any of them
}