rule TTP_XOR_QUAD_CurrentVersionRun_9583 {
  strings:
    $key_9583 = { c6 ec [2] e2 e2 [2] c9 ce [2] e7 ec [2] f3 f7 [2] fc ed [2] e2 f0 [2] e0 f1 [2] fb f7 [2] e7 f0 [2] fb df }

  condition:
    any of them
}