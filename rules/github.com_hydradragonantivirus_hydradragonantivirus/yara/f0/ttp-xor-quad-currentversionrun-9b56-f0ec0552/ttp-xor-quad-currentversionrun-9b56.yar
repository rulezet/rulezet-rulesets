rule TTP_XOR_QUAD_CurrentVersionRun_9b56 {
  strings:
    $key_9b56 = { c8 39 [2] ec 37 [2] c7 1b [2] e9 39 [2] fd 22 [2] f2 38 [2] ec 25 [2] ee 24 [2] f5 22 [2] e9 25 [2] f5 0a }

  condition:
    any of them
}