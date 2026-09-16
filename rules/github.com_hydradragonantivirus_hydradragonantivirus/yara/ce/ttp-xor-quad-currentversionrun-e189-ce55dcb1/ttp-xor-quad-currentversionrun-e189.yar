rule TTP_XOR_QUAD_CurrentVersionRun_e189 {
  strings:
    $key_e189 = { b2 e6 [2] 96 e8 [2] bd c4 [2] 93 e6 [2] 87 fd [2] 88 e7 [2] 96 fa [2] 94 fb [2] 8f fd [2] 93 fa [2] 8f d5 }

  condition:
    any of them
}