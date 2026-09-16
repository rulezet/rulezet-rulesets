rule TTP_XOR_QUAD_CurrentVersionRun_84a1 {
  strings:
    $key_84a1 = { d7 ce [2] f3 c0 [2] d8 ec [2] f6 ce [2] e2 d5 [2] ed cf [2] f3 d2 [2] f1 d3 [2] ea d5 [2] f6 d2 [2] ea fd }

  condition:
    any of them
}