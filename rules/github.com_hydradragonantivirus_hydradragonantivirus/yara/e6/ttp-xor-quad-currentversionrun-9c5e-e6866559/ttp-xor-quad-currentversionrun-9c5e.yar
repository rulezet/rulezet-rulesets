rule TTP_XOR_QUAD_CurrentVersionRun_9c5e {
  strings:
    $key_9c5e = { cf 31 [2] eb 3f [2] c0 13 [2] ee 31 [2] fa 2a [2] f5 30 [2] eb 2d [2] e9 2c [2] f2 2a [2] ee 2d [2] f2 02 }

  condition:
    any of them
}