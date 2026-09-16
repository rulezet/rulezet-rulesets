rule TTP_XOR_QUAD_CurrentVersionRun_9b54 {
  strings:
    $key_9b54 = { c8 3b [2] ec 35 [2] c7 19 [2] e9 3b [2] fd 20 [2] f2 3a [2] ec 27 [2] ee 26 [2] f5 20 [2] e9 27 [2] f5 08 }

  condition:
    any of them
}