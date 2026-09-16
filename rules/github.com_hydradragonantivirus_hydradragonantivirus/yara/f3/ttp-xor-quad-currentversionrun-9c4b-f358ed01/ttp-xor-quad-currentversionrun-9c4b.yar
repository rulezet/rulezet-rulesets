rule TTP_XOR_QUAD_CurrentVersionRun_9c4b {
  strings:
    $key_9c4b = { cf 24 [2] eb 2a [2] c0 06 [2] ee 24 [2] fa 3f [2] f5 25 [2] eb 38 [2] e9 39 [2] f2 3f [2] ee 38 [2] f2 17 }

  condition:
    any of them
}