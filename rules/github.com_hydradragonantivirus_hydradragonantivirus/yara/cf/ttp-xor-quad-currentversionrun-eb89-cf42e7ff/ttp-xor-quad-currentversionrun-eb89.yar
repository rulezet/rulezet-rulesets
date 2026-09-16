rule TTP_XOR_QUAD_CurrentVersionRun_eb89 {
  strings:
    $key_eb89 = { b8 e6 [2] 9c e8 [2] b7 c4 [2] 99 e6 [2] 8d fd [2] 82 e7 [2] 9c fa [2] 9e fb [2] 85 fd [2] 99 fa [2] 85 d5 }

  condition:
    any of them
}