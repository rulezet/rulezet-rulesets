rule TTP_XOR_QUAD_CurrentVersionRun_f388 {
  strings:
    $key_f388 = { a0 e7 [2] 84 e9 [2] af c5 [2] 81 e7 [2] 95 fc [2] 9a e6 [2] 84 fb [2] 86 fa [2] 9d fc [2] 81 fb [2] 9d d4 }

  condition:
    any of them
}