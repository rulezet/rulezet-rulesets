rule TTP_XOR_QUAD_CurrentVersionRun_9c38 {
  strings:
    $key_9c38 = { cf 57 [2] eb 59 [2] c0 75 [2] ee 57 [2] fa 4c [2] f5 56 [2] eb 4b [2] e9 4a [2] f2 4c [2] ee 4b [2] f2 64 }

  condition:
    any of them
}