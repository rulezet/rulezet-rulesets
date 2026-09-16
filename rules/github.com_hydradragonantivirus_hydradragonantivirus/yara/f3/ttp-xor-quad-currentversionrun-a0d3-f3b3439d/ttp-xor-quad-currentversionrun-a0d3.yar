rule TTP_XOR_QUAD_CurrentVersionRun_a0d3 {
  strings:
    $key_a0d3 = { f3 bc [2] d7 b2 [2] fc 9e [2] d2 bc [2] c6 a7 [2] c9 bd [2] d7 a0 [2] d5 a1 [2] ce a7 [2] d2 a0 [2] ce 8f }

  condition:
    any of them
}