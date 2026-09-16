rule TTP_XOR_QUAD_CurrentVersionRun_9c75 {
  strings:
    $key_9c75 = { cf 1a [2] eb 14 [2] c0 38 [2] ee 1a [2] fa 01 [2] f5 1b [2] eb 06 [2] e9 07 [2] f2 01 [2] ee 06 [2] f2 29 }

  condition:
    any of them
}