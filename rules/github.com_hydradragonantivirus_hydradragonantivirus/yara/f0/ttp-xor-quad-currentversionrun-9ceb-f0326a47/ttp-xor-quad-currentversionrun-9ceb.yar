rule TTP_XOR_QUAD_CurrentVersionRun_9ceb {
  strings:
    $key_9ceb = { cf 84 [2] eb 8a [2] c0 a6 [2] ee 84 [2] fa 9f [2] f5 85 [2] eb 98 [2] e9 99 [2] f2 9f [2] ee 98 [2] f2 b7 }

  condition:
    any of them
}