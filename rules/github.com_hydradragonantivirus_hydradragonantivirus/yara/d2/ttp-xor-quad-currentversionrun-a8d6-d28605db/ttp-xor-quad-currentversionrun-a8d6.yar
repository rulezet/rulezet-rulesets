rule TTP_XOR_QUAD_CurrentVersionRun_a8d6 {
  strings:
    $key_a8d6 = { fb b9 [2] df b7 [2] f4 9b [2] da b9 [2] ce a2 [2] c1 b8 [2] df a5 [2] dd a4 [2] c6 a2 [2] da a5 [2] c6 8a }

  condition:
    any of them
}