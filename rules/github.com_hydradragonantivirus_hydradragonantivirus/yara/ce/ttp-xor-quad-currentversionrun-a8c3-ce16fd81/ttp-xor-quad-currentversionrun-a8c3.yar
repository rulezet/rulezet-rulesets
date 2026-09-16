rule TTP_XOR_QUAD_CurrentVersionRun_a8c3 {
  strings:
    $key_a8c3 = { fb ac [2] df a2 [2] f4 8e [2] da ac [2] ce b7 [2] c1 ad [2] df b0 [2] dd b1 [2] c6 b7 [2] da b0 [2] c6 9f }

  condition:
    any of them
}