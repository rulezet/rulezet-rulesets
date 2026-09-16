rule TTP_XOR_QUAD_CurrentVersionRun_af94 {
  strings:
    $key_af94 = { fc fb [2] d8 f5 [2] f3 d9 [2] dd fb [2] c9 e0 [2] c6 fa [2] d8 e7 [2] da e6 [2] c1 e0 [2] dd e7 [2] c1 c8 }

  condition:
    any of them
}