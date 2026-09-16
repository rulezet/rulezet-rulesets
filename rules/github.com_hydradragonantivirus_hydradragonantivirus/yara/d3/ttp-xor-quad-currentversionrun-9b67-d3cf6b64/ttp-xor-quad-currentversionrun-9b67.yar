rule TTP_XOR_QUAD_CurrentVersionRun_9b67 {
  strings:
    $key_9b67 = { c8 08 [2] ec 06 [2] c7 2a [2] e9 08 [2] fd 13 [2] f2 09 [2] ec 14 [2] ee 15 [2] f5 13 [2] e9 14 [2] f5 3b }

  condition:
    any of them
}