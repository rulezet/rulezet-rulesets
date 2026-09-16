rule TTP_XOR_QUAD_CurrentVersionRun_9b79 {
  strings:
    $key_9b79 = { c8 16 [2] ec 18 [2] c7 34 [2] e9 16 [2] fd 0d [2] f2 17 [2] ec 0a [2] ee 0b [2] f5 0d [2] e9 0a [2] f5 25 }

  condition:
    any of them
}