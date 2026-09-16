rule TTP_XOR_QUAD_CurrentVersionRun_9c7e {
  strings:
    $key_9c7e = { cf 11 [2] eb 1f [2] c0 33 [2] ee 11 [2] fa 0a [2] f5 10 [2] eb 0d [2] e9 0c [2] f2 0a [2] ee 0d [2] f2 22 }

  condition:
    any of them
}