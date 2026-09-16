rule TTP_XOR_QUAD_CurrentVersionRun_4488 {
  strings:
    $key_4488 = { 17 e7 [2] 33 e9 [2] 18 c5 [2] 36 e7 [2] 22 fc [2] 2d e6 [2] 33 fb [2] 31 fa [2] 2a fc [2] 36 fb [2] 2a d4 }

  condition:
    any of them
}