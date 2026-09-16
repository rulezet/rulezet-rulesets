rule TTP_XOR_QUAD_CurrentVersionRun_ce89 {
  strings:
    $key_ce89 = { 9d e6 [2] b9 e8 [2] 92 c4 [2] bc e6 [2] a8 fd [2] a7 e7 [2] b9 fa [2] bb fb [2] a0 fd [2] bc fa [2] a0 d5 }

  condition:
    any of them
}