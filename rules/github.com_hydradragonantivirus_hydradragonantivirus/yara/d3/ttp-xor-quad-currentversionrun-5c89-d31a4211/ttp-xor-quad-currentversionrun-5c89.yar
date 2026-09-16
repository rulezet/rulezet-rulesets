rule TTP_XOR_QUAD_CurrentVersionRun_5c89 {
  strings:
    $key_5c89 = { 0f e6 [2] 2b e8 [2] 00 c4 [2] 2e e6 [2] 3a fd [2] 35 e7 [2] 2b fa [2] 29 fb [2] 32 fd [2] 2e fa [2] 32 d5 }

  condition:
    any of them
}