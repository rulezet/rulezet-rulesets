rule TTP_XOR_QUAD_CurrentVersionRun_0c89 {
  strings:
    $key_0c89 = { 5f e6 [2] 7b e8 [2] 50 c4 [2] 7e e6 [2] 6a fd [2] 65 e7 [2] 7b fa [2] 79 fb [2] 62 fd [2] 7e fa [2] 62 d5 }

  condition:
    any of them
}