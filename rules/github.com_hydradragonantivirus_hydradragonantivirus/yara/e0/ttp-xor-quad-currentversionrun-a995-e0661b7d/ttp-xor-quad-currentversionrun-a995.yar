rule TTP_XOR_QUAD_CurrentVersionRun_a995 {
  strings:
    $key_a995 = { fa fa [2] de f4 [2] f5 d8 [2] db fa [2] cf e1 [2] c0 fb [2] de e6 [2] dc e7 [2] c7 e1 [2] db e6 [2] c7 c9 }

  condition:
    any of them
}