rule TTP_XOR_QUAD_CurrentVersionRun_8988 {
  strings:
    $key_8988 = { da e7 [2] fe e9 [2] d5 c5 [2] fb e7 [2] ef fc [2] e0 e6 [2] fe fb [2] fc fa [2] e7 fc [2] fb fb [2] e7 d4 }

  condition:
    any of them
}