rule TTP_XOR_QUAD_CurrentVersionRun_9b72 {
  strings:
    $key_9b72 = { c8 1d [2] ec 13 [2] c7 3f [2] e9 1d [2] fd 06 [2] f2 1c [2] ec 01 [2] ee 00 [2] f5 06 [2] e9 01 [2] f5 2e }

  condition:
    any of them
}