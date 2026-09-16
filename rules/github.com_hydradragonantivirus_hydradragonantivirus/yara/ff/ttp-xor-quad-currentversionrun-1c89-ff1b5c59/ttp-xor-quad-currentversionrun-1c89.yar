rule TTP_XOR_QUAD_CurrentVersionRun_1c89 {
  strings:
    $key_1c89 = { 4f e6 [2] 6b e8 [2] 40 c4 [2] 6e e6 [2] 7a fd [2] 75 e7 [2] 6b fa [2] 69 fb [2] 72 fd [2] 6e fa [2] 72 d5 }

  condition:
    any of them
}