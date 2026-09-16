rule TTP_XOR_QUAD_CurrentVersionRun_9394 {
  strings:
    $key_9394 = { c0 fb [2] e4 f5 [2] cf d9 [2] e1 fb [2] f5 e0 [2] fa fa [2] e4 e7 [2] e6 e6 [2] fd e0 [2] e1 e7 [2] fd c8 }

  condition:
    any of them
}