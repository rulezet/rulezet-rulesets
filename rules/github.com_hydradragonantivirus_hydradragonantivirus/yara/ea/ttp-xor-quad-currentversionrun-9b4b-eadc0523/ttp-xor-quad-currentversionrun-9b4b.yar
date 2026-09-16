rule TTP_XOR_QUAD_CurrentVersionRun_9b4b {
  strings:
    $key_9b4b = { c8 24 [2] ec 2a [2] c7 06 [2] e9 24 [2] fd 3f [2] f2 25 [2] ec 38 [2] ee 39 [2] f5 3f [2] e9 38 [2] f5 17 }

  condition:
    any of them
}