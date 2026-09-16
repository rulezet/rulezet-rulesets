rule TTP_XOR_QUAD_CurrentVersionRun_e389 {
  strings:
    $key_e389 = { b0 e6 [2] 94 e8 [2] bf c4 [2] 91 e6 [2] 85 fd [2] 8a e7 [2] 94 fa [2] 96 fb [2] 8d fd [2] 91 fa [2] 8d d5 }

  condition:
    any of them
}