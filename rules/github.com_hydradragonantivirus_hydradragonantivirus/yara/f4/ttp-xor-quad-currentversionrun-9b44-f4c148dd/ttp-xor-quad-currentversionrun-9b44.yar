rule TTP_XOR_QUAD_CurrentVersionRun_9b44 {
  strings:
    $key_9b44 = { c8 2b [2] ec 25 [2] c7 09 [2] e9 2b [2] fd 30 [2] f2 2a [2] ec 37 [2] ee 36 [2] f5 30 [2] e9 37 [2] f5 18 }

  condition:
    any of them
}