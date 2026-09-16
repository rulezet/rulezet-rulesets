rule TTP_XOR_QUAD_CurrentVersionRun_9b34 {
  strings:
    $key_9b34 = { c8 5b [2] ec 55 [2] c7 79 [2] e9 5b [2] fd 40 [2] f2 5a [2] ec 47 [2] ee 46 [2] f5 40 [2] e9 47 [2] f5 68 }

  condition:
    any of them
}