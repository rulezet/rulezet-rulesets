rule TTP_XOR_QUAD_CurrentVersionRun_9c5f {
  strings:
    $key_9c5f = { cf 30 [2] eb 3e [2] c0 12 [2] ee 30 [2] fa 2b [2] f5 31 [2] eb 2c [2] e9 2d [2] f2 2b [2] ee 2c [2] f2 03 }

  condition:
    any of them
}