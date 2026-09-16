rule TTP_XOR_QUAD_CurrentVersionRun_9587 {
  strings:
    $key_9587 = { c6 e8 [2] e2 e6 [2] c9 ca [2] e7 e8 [2] f3 f3 [2] fc e9 [2] e2 f4 [2] e0 f5 [2] fb f3 [2] e7 f4 [2] fb db }

  condition:
    any of them
}