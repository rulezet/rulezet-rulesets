rule TTP_XOR_QUAD_CurrentVersionRun_0389 {
  strings:
    $key_0389 = { 50 e6 [2] 74 e8 [2] 5f c4 [2] 71 e6 [2] 65 fd [2] 6a e7 [2] 74 fa [2] 76 fb [2] 6d fd [2] 71 fa [2] 6d d5 }

  condition:
    any of them
}