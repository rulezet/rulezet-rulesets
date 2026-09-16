rule TTP_XOR_QUAD_CurrentVersionRun_6788 {
  strings:
    $key_6788 = { 34 e7 [2] 10 e9 [2] 3b c5 [2] 15 e7 [2] 01 fc [2] 0e e6 [2] 10 fb [2] 12 fa [2] 09 fc [2] 15 fb [2] 09 d4 }

  condition:
    any of them
}