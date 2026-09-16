rule TTP_XOR_QUAD_CurrentVersionRun_8e95 {
  strings:
    $key_8e95 = { dd fa [2] f9 f4 [2] d2 d8 [2] fc fa [2] e8 e1 [2] e7 fb [2] f9 e6 [2] fb e7 [2] e0 e1 [2] fc e6 [2] e0 c9 }

  condition:
    any of them
}