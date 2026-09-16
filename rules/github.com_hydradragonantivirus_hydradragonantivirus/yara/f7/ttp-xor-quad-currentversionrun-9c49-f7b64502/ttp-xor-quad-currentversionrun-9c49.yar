rule TTP_XOR_QUAD_CurrentVersionRun_9c49 {
  strings:
    $key_9c49 = { cf 26 [2] eb 28 [2] c0 04 [2] ee 26 [2] fa 3d [2] f5 27 [2] eb 3a [2] e9 3b [2] f2 3d [2] ee 3a [2] f2 15 }

  condition:
    any of them
}