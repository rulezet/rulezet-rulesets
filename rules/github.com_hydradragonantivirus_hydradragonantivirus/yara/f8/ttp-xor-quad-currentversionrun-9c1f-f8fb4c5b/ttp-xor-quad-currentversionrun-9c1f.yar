rule TTP_XOR_QUAD_CurrentVersionRun_9c1f {
  strings:
    $key_9c1f = { cf 70 [2] eb 7e [2] c0 52 [2] ee 70 [2] fa 6b [2] f5 71 [2] eb 6c [2] e9 6d [2] f2 6b [2] ee 6c [2] f2 43 }

  condition:
    any of them
}