rule TTP_XOR_QUAD_CurrentVersionRun_ee89 {
  strings:
    $key_ee89 = { bd e6 [2] 99 e8 [2] b2 c4 [2] 9c e6 [2] 88 fd [2] 87 e7 [2] 99 fa [2] 9b fb [2] 80 fd [2] 9c fa [2] 80 d5 }

  condition:
    any of them
}