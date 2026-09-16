rule TTP_XOR_QUAD_CurrentVersionRun_9494 {
  strings:
    $key_9494 = { c7 fb [2] e3 f5 [2] c8 d9 [2] e6 fb [2] f2 e0 [2] fd fa [2] e3 e7 [2] e1 e6 [2] fa e0 [2] e6 e7 [2] fa c8 }

  condition:
    any of them
}