rule TTP_XOR_QUAD_CurrentVersionRun_9598 {
  strings:
    $key_9598 = { c6 f7 [2] e2 f9 [2] c9 d5 [2] e7 f7 [2] f3 ec [2] fc f6 [2] e2 eb [2] e0 ea [2] fb ec [2] e7 eb [2] fb c4 }

  condition:
    any of them
}