rule TTP_XOR_QUAD_CurrentVersionRun_9cff {
  strings:
    $key_9cff = { cf 90 [2] eb 9e [2] c0 b2 [2] ee 90 [2] fa 8b [2] f5 91 [2] eb 8c [2] e9 8d [2] f2 8b [2] ee 8c [2] f2 a3 }

  condition:
    any of them
}