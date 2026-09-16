rule TTP_XOR_QUAD_CurrentVersionRun_b0d3 {
  strings:
    $key_b0d3 = { e3 bc [2] c7 b2 [2] ec 9e [2] c2 bc [2] d6 a7 [2] d9 bd [2] c7 a0 [2] c5 a1 [2] de a7 [2] c2 a0 [2] de 8f }

  condition:
    any of them
}