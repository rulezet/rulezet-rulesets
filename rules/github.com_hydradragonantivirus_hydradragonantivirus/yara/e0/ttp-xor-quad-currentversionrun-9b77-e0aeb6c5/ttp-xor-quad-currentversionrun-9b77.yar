rule TTP_XOR_QUAD_CurrentVersionRun_9b77 {
  strings:
    $key_9b77 = { c8 18 [2] ec 16 [2] c7 3a [2] e9 18 [2] fd 03 [2] f2 19 [2] ec 04 [2] ee 05 [2] f5 03 [2] e9 04 [2] f5 2b }

  condition:
    any of them
}