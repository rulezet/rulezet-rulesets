rule TTP_XOR_QUAD_CurrentVersionRun_9b63 {
  strings:
    $key_9b63 = { c8 0c [2] ec 02 [2] c7 2e [2] e9 0c [2] fd 17 [2] f2 0d [2] ec 10 [2] ee 11 [2] f5 17 [2] e9 10 [2] f5 3f }

  condition:
    any of them
}