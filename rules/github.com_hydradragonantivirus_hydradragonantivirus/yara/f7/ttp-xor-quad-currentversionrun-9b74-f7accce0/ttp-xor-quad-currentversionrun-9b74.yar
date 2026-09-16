rule TTP_XOR_QUAD_CurrentVersionRun_9b74 {
  strings:
    $key_9b74 = { c8 1b [2] ec 15 [2] c7 39 [2] e9 1b [2] fd 00 [2] f2 1a [2] ec 07 [2] ee 06 [2] f5 00 [2] e9 07 [2] f5 28 }

  condition:
    any of them
}