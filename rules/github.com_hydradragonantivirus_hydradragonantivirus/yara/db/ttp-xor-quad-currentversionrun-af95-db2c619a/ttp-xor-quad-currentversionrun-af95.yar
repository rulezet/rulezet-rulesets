rule TTP_XOR_QUAD_CurrentVersionRun_af95 {
  strings:
    $key_af95 = { fc fa [2] d8 f4 [2] f3 d8 [2] dd fa [2] c9 e1 [2] c6 fb [2] d8 e6 [2] da e7 [2] c1 e1 [2] dd e6 [2] c1 c9 }

  condition:
    any of them
}