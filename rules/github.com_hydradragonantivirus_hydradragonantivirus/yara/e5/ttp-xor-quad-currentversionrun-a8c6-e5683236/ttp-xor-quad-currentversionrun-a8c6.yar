rule TTP_XOR_QUAD_CurrentVersionRun_a8c6 {
  strings:
    $key_a8c6 = { fb a9 [2] df a7 [2] f4 8b [2] da a9 [2] ce b2 [2] c1 a8 [2] df b5 [2] dd b4 [2] c6 b2 [2] da b5 [2] c6 9a }

  condition:
    any of them
}