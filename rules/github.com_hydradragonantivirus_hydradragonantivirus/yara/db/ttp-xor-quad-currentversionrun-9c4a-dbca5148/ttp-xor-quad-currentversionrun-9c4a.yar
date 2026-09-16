rule TTP_XOR_QUAD_CurrentVersionRun_9c4a {
  strings:
    $key_9c4a = { cf 25 [2] eb 2b [2] c0 07 [2] ee 25 [2] fa 3e [2] f5 24 [2] eb 39 [2] e9 38 [2] f2 3e [2] ee 39 [2] f2 16 }

  condition:
    any of them
}