rule TTP_XOR_QUAD_CurrentVersionRun_ac95 {
  strings:
    $key_ac95 = { ff fa [2] db f4 [2] f0 d8 [2] de fa [2] ca e1 [2] c5 fb [2] db e6 [2] d9 e7 [2] c2 e1 [2] de e6 [2] c2 c9 }

  condition:
    any of them
}