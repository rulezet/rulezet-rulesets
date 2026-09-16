rule TTP_XOR_QUAD_CurrentVersionRun_9c32 {
  strings:
    $key_9c32 = { cf 5d [2] eb 53 [2] c0 7f [2] ee 5d [2] fa 46 [2] f5 5c [2] eb 41 [2] e9 40 [2] f2 46 [2] ee 41 [2] f2 6e }

  condition:
    any of them
}