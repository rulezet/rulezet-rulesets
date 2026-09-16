rule TTP_XOR_QUAD_CurrentVersionRun_9fb6 {
  strings:
    $key_9fb6 = { cc d9 [2] e8 d7 [2] c3 fb [2] ed d9 [2] f9 c2 [2] f6 d8 [2] e8 c5 [2] ea c4 [2] f1 c2 [2] ed c5 [2] f1 ea }

  condition:
    any of them
}