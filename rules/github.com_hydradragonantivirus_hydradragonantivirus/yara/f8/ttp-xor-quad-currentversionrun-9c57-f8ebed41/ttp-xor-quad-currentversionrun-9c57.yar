rule TTP_XOR_QUAD_CurrentVersionRun_9c57 {
  strings:
    $key_9c57 = { cf 38 [2] eb 36 [2] c0 1a [2] ee 38 [2] fa 23 [2] f5 39 [2] eb 24 [2] e9 25 [2] f2 23 [2] ee 24 [2] f2 0b }

  condition:
    any of them
}