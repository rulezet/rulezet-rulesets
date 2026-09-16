rule TTP_XOR_QUAD_CurrentVersionRun_9503 {
  strings:
    $key_9503 = { c6 6c [2] e2 62 [2] c9 4e [2] e7 6c [2] f3 77 [2] fc 6d [2] e2 70 [2] e0 71 [2] fb 77 [2] e7 70 [2] fb 5f }

  condition:
    any of them
}