rule TTP_XOR_QUAD_CurrentVersionRun_8994 {
  strings:
    $key_8994 = { da fb [2] fe f5 [2] d5 d9 [2] fb fb [2] ef e0 [2] e0 fa [2] fe e7 [2] fc e6 [2] e7 e0 [2] fb e7 [2] e7 c8 }

  condition:
    any of them
}