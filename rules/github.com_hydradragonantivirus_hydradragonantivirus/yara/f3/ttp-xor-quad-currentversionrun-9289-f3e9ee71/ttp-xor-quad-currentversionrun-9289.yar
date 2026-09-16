rule TTP_XOR_QUAD_CurrentVersionRun_9289 {
  strings:
    $key_9289 = { c1 e6 [2] e5 e8 [2] ce c4 [2] e0 e6 [2] f4 fd [2] fb e7 [2] e5 fa [2] e7 fb [2] fc fd [2] e0 fa [2] fc d5 }

  condition:
    any of them
}