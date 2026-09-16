rule TTP_XOR_QUAD_CurrentVersionRun_9f88 {
  strings:
    $key_9f88 = { cc e7 [2] e8 e9 [2] c3 c5 [2] ed e7 [2] f9 fc [2] f6 e6 [2] e8 fb [2] ea fa [2] f1 fc [2] ed fb [2] f1 d4 }

  condition:
    any of them
}