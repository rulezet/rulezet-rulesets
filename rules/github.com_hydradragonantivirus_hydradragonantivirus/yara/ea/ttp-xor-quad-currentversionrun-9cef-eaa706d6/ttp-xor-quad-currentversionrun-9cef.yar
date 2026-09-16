rule TTP_XOR_QUAD_CurrentVersionRun_9cef {
  strings:
    $key_9cef = { cf 80 [2] eb 8e [2] c0 a2 [2] ee 80 [2] fa 9b [2] f5 81 [2] eb 9c [2] e9 9d [2] f2 9b [2] ee 9c [2] f2 b3 }

  condition:
    any of them
}