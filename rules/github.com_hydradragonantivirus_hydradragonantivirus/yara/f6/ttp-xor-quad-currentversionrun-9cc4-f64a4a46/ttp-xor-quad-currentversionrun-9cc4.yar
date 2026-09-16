rule TTP_XOR_QUAD_CurrentVersionRun_9cc4 {
  strings:
    $key_9cc4 = { cf ab [2] eb a5 [2] c0 89 [2] ee ab [2] fa b0 [2] f5 aa [2] eb b7 [2] e9 b6 [2] f2 b0 [2] ee b7 [2] f2 98 }

  condition:
    any of them
}