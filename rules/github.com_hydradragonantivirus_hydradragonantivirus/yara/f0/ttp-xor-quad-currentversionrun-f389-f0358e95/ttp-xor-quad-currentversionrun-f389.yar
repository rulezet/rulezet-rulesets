rule TTP_XOR_QUAD_CurrentVersionRun_f389 {
  strings:
    $key_f389 = { a0 e6 [2] 84 e8 [2] af c4 [2] 81 e6 [2] 95 fd [2] 9a e7 [2] 84 fa [2] 86 fb [2] 9d fd [2] 81 fa [2] 9d d5 }

  condition:
    any of them
}