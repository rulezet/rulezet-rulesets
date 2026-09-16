rule TTP_XOR_QUAD_CurrentVersionRun_9ce5 {
  strings:
    $key_9ce5 = { cf 8a [2] eb 84 [2] c0 a8 [2] ee 8a [2] fa 91 [2] f5 8b [2] eb 96 [2] e9 97 [2] f2 91 [2] ee 96 [2] f2 b9 }

  condition:
    any of them
}