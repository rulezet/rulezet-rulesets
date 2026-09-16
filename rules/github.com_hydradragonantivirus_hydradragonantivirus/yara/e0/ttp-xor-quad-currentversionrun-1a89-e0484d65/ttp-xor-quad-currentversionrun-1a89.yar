rule TTP_XOR_QUAD_CurrentVersionRun_1a89 {
  strings:
    $key_1a89 = { 49 e6 [2] 6d e8 [2] 46 c4 [2] 68 e6 [2] 7c fd [2] 73 e7 [2] 6d fa [2] 6f fb [2] 74 fd [2] 68 fa [2] 74 d5 }

  condition:
    any of them
}