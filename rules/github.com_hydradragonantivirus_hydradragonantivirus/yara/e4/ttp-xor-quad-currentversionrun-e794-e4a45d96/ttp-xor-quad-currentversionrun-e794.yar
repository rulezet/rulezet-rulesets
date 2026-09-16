rule TTP_XOR_QUAD_CurrentVersionRun_e794 {
  strings:
    $key_e794 = { b4 fb [2] 90 f5 [2] bb d9 [2] 95 fb [2] 81 e0 [2] 8e fa [2] 90 e7 [2] 92 e6 [2] 89 e0 [2] 95 e7 [2] 89 c8 }

  condition:
    any of them
}