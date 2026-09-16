rule TTP_XOR_QUAD_CurrentVersionRun_9fb5 {
  strings:
    $key_9fb5 = { cc da [2] e8 d4 [2] c3 f8 [2] ed da [2] f9 c1 [2] f6 db [2] e8 c6 [2] ea c7 [2] f1 c1 [2] ed c6 [2] f1 e9 }

  condition:
    any of them
}