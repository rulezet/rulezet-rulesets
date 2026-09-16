rule TTP_XOR_QUAD_CurrentVersionRun_ac89 {
  strings:
    $key_ac89 = { ff e6 [2] db e8 [2] f0 c4 [2] de e6 [2] ca fd [2] c5 e7 [2] db fa [2] d9 fb [2] c2 fd [2] de fa [2] c2 d5 }

  condition:
    any of them
}