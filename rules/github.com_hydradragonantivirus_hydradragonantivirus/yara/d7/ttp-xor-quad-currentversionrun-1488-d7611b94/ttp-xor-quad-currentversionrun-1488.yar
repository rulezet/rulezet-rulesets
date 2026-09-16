rule TTP_XOR_QUAD_CurrentVersionRun_1488 {
  strings:
    $key_1488 = { 47 e7 [2] 63 e9 [2] 48 c5 [2] 66 e7 [2] 72 fc [2] 7d e6 [2] 63 fb [2] 61 fa [2] 7a fc [2] 66 fb [2] 7a d4 }

  condition:
    any of them
}