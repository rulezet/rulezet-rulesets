rule TTP_XOR_QUAD_CurrentVersionRun_9b1b {
  strings:
    $key_9b1b = { c8 74 [2] ec 7a [2] c7 56 [2] e9 74 [2] fd 6f [2] f2 75 [2] ec 68 [2] ee 69 [2] f5 6f [2] e9 68 [2] f5 47 }

  condition:
    any of them
}