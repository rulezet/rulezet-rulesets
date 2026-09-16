rule TTP_XOR_QUAD_CurrentVersionRun_3489 {
  strings:
    $key_3489 = { 67 e6 [2] 43 e8 [2] 68 c4 [2] 46 e6 [2] 52 fd [2] 5d e7 [2] 43 fa [2] 41 fb [2] 5a fd [2] 46 fa [2] 5a d5 }

  condition:
    any of them
}