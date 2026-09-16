rule TTP_XOR_QUAD_CurrentVersionRun_9b47 {
  strings:
    $key_9b47 = { c8 28 [2] ec 26 [2] c7 0a [2] e9 28 [2] fd 33 [2] f2 29 [2] ec 34 [2] ee 35 [2] f5 33 [2] e9 34 [2] f5 1b }

  condition:
    any of them
}