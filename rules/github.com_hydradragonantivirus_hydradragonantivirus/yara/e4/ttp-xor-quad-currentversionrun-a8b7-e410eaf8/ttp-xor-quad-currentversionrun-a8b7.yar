rule TTP_XOR_QUAD_CurrentVersionRun_a8b7 {
  strings:
    $key_a8b7 = { fb d8 [2] df d6 [2] f4 fa [2] da d8 [2] ce c3 [2] c1 d9 [2] df c4 [2] dd c5 [2] c6 c3 [2] da c4 [2] c6 eb }

  condition:
    any of them
}