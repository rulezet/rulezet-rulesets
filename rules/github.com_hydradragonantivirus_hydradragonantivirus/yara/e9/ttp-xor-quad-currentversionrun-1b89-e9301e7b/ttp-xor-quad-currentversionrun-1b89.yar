rule TTP_XOR_QUAD_CurrentVersionRun_1b89 {
  strings:
    $key_1b89 = { 48 e6 [2] 6c e8 [2] 47 c4 [2] 69 e6 [2] 7d fd [2] 72 e7 [2] 6c fa [2] 6e fb [2] 75 fd [2] 69 fa [2] 75 d5 }

  condition:
    any of them
}