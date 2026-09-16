rule TTP_XOR_QUAD_CurrentVersionRun_a8d4 {
  strings:
    $key_a8d4 = { fb bb [2] df b5 [2] f4 99 [2] da bb [2] ce a0 [2] c1 ba [2] df a7 [2] dd a6 [2] c6 a0 [2] da a7 [2] c6 88 }

  condition:
    any of them
}