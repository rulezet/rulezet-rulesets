rule TTP_XOR_QUAD_CurrentVersionRun_9ce0 {
  strings:
    $key_9ce0 = { cf 8f [2] eb 81 [2] c0 ad [2] ee 8f [2] fa 94 [2] f5 8e [2] eb 93 [2] e9 92 [2] f2 94 [2] ee 93 [2] f2 bc }

  condition:
    any of them
}