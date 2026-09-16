rule TTP_XOR_QUAD_CurrentVersionRun_9513 {
  strings:
    $key_9513 = { c6 7c [2] e2 72 [2] c9 5e [2] e7 7c [2] f3 67 [2] fc 7d [2] e2 60 [2] e0 61 [2] fb 67 [2] e7 60 [2] fb 4f }

  condition:
    any of them
}