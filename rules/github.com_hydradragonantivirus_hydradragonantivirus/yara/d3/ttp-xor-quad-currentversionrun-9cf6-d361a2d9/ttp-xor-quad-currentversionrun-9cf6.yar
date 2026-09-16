rule TTP_XOR_QUAD_CurrentVersionRun_9cf6 {
  strings:
    $key_9cf6 = { cf 99 [2] eb 97 [2] c0 bb [2] ee 99 [2] fa 82 [2] f5 98 [2] eb 85 [2] e9 84 [2] f2 82 [2] ee 85 [2] f2 aa }

  condition:
    any of them
}