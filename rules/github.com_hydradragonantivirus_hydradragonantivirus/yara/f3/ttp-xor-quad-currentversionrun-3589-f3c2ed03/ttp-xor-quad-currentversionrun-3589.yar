rule TTP_XOR_QUAD_CurrentVersionRun_3589 {
  strings:
    $key_3589 = { 66 e6 [2] 42 e8 [2] 69 c4 [2] 47 e6 [2] 53 fd [2] 5c e7 [2] 42 fa [2] 40 fb [2] 5b fd [2] 47 fa [2] 5b d5 }

  condition:
    any of them
}