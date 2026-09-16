rule TTP_XOR_QUAD_CurrentVersionRun_9ce8 {
  strings:
    $key_9ce8 = { cf 87 [2] eb 89 [2] c0 a5 [2] ee 87 [2] fa 9c [2] f5 86 [2] eb 9b [2] e9 9a [2] f2 9c [2] ee 9b [2] f2 b4 }

  condition:
    any of them
}