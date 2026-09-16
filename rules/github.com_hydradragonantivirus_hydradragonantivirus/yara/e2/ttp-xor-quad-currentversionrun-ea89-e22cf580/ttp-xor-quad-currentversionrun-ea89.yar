rule TTP_XOR_QUAD_CurrentVersionRun_ea89 {
  strings:
    $key_ea89 = { b9 e6 [2] 9d e8 [2] b6 c4 [2] 98 e6 [2] 8c fd [2] 83 e7 [2] 9d fa [2] 9f fb [2] 84 fd [2] 98 fa [2] 84 d5 }

  condition:
    any of them
}