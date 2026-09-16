rule TTP_XOR_QUAD_CurrentVersionRun_a8d7 {
  strings:
    $key_a8d7 = { fb b8 [2] df b6 [2] f4 9a [2] da b8 [2] ce a3 [2] c1 b9 [2] df a4 [2] dd a5 [2] c6 a3 [2] da a4 [2] c6 8b }

  condition:
    any of them
}