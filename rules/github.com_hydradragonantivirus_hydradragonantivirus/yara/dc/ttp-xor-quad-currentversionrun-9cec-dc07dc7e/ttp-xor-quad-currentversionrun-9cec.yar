rule TTP_XOR_QUAD_CurrentVersionRun_9cec {
  strings:
    $key_9cec = { cf 83 [2] eb 8d [2] c0 a1 [2] ee 83 [2] fa 98 [2] f5 82 [2] eb 9f [2] e9 9e [2] f2 98 [2] ee 9f [2] f2 b0 }

  condition:
    any of them
}