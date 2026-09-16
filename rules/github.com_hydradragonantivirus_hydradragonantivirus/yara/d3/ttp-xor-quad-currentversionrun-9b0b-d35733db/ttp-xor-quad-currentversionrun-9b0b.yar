rule TTP_XOR_QUAD_CurrentVersionRun_9b0b {
  strings:
    $key_9b0b = { c8 64 [2] ec 6a [2] c7 46 [2] e9 64 [2] fd 7f [2] f2 65 [2] ec 78 [2] ee 79 [2] f5 7f [2] e9 78 [2] f5 57 }

  condition:
    any of them
}