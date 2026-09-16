rule TTP_XOR_QUAD_CurrentVersionRun_7b89 {
  strings:
    $key_7b89 = { 28 e6 [2] 0c e8 [2] 27 c4 [2] 09 e6 [2] 1d fd [2] 12 e7 [2] 0c fa [2] 0e fb [2] 15 fd [2] 09 fa [2] 15 d5 }

  condition:
    any of them
}