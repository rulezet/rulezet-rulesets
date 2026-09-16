rule TTP_XOR_QUAD_CurrentVersionRun_9b37 {
  strings:
    $key_9b37 = { c8 58 [2] ec 56 [2] c7 7a [2] e9 58 [2] fd 43 [2] f2 59 [2] ec 44 [2] ee 45 [2] f5 43 [2] e9 44 [2] f5 6b }

  condition:
    any of them
}