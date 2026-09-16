rule TTP_XOR_QUAD_CurrentVersionRun_c589 {
  strings:
    $key_c589 = { 96 e6 [2] b2 e8 [2] 99 c4 [2] b7 e6 [2] a3 fd [2] ac e7 [2] b2 fa [2] b0 fb [2] ab fd [2] b7 fa [2] ab d5 }

  condition:
    any of them
}