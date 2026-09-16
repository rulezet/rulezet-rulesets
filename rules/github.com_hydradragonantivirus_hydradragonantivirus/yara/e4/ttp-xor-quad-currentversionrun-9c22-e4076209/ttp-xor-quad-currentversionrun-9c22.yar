rule TTP_XOR_QUAD_CurrentVersionRun_9c22 {
  strings:
    $key_9c22 = { cf 4d [2] eb 43 [2] c0 6f [2] ee 4d [2] fa 56 [2] f5 4c [2] eb 51 [2] e9 50 [2] f2 56 [2] ee 51 [2] f2 7e }

  condition:
    any of them
}