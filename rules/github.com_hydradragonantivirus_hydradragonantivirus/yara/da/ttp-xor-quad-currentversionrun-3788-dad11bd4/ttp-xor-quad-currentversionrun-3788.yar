rule TTP_XOR_QUAD_CurrentVersionRun_3788 {
  strings:
    $key_3788 = { 64 e7 [2] 40 e9 [2] 6b c5 [2] 45 e7 [2] 51 fc [2] 5e e6 [2] 40 fb [2] 42 fa [2] 59 fc [2] 45 fb [2] 59 d4 }

  condition:
    any of them
}