rule TTP_XOR_QUAD_CurrentVersionRun_7389 {
  strings:
    $key_7389 = { 20 e6 [2] 04 e8 [2] 2f c4 [2] 01 e6 [2] 15 fd [2] 1a e7 [2] 04 fa [2] 06 fb [2] 1d fd [2] 01 fa [2] 1d d5 }

  condition:
    any of them
}