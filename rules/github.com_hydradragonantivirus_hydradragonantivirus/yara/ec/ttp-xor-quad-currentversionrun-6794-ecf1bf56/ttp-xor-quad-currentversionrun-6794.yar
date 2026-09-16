rule TTP_XOR_QUAD_CurrentVersionRun_6794 {
  strings:
    $key_6794 = { 34 fb [2] 10 f5 [2] 3b d9 [2] 15 fb [2] 01 e0 [2] 0e fa [2] 10 e7 [2] 12 e6 [2] 09 e0 [2] 15 e7 [2] 09 c8 }

  condition:
    any of them
}