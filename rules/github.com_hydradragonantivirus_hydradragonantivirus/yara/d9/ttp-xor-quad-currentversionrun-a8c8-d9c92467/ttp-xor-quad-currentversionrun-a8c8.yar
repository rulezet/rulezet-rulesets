rule TTP_XOR_QUAD_CurrentVersionRun_a8c8 {
  strings:
    $key_a8c8 = { fb a7 [2] df a9 [2] f4 85 [2] da a7 [2] ce bc [2] c1 a6 [2] df bb [2] dd ba [2] c6 bc [2] da bb [2] c6 94 }

  condition:
    any of them
}