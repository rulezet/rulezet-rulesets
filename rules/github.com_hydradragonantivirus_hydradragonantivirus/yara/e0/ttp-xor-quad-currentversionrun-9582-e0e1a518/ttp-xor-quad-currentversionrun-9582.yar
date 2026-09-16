rule TTP_XOR_QUAD_CurrentVersionRun_9582 {
  strings:
    $key_9582 = { c6 ed [2] e2 e3 [2] c9 cf [2] e7 ed [2] f3 f6 [2] fc ec [2] e2 f1 [2] e0 f0 [2] fb f6 [2] e7 f1 [2] fb de }

  condition:
    any of them
}