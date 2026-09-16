rule TTP_XOR_QUAD_CurrentVersionRun_2095 {
  strings:
    $key_2095 = { 73 fa [2] 57 f4 [2] 7c d8 [2] 52 fa [2] 46 e1 [2] 49 fb [2] 57 e6 [2] 55 e7 [2] 4e e1 [2] 52 e6 [2] 4e c9 }

  condition:
    any of them
}