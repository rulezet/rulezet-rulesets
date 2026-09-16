rule TTP_XOR_QUAD_CurrentVersionRun_6289 {
  strings:
    $key_6289 = { 31 e6 [2] 15 e8 [2] 3e c4 [2] 10 e6 [2] 04 fd [2] 0b e7 [2] 15 fa [2] 17 fb [2] 0c fd [2] 10 fa [2] 0c d5 }

  condition:
    any of them
}