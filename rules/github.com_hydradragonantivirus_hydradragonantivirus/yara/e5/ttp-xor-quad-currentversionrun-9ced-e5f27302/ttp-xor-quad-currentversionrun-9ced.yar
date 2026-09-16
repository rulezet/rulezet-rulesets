rule TTP_XOR_QUAD_CurrentVersionRun_9ced {
  strings:
    $key_9ced = { cf 82 [2] eb 8c [2] c0 a0 [2] ee 82 [2] fa 99 [2] f5 83 [2] eb 9e [2] e9 9f [2] f2 99 [2] ee 9e [2] f2 b1 }

  condition:
    any of them
}