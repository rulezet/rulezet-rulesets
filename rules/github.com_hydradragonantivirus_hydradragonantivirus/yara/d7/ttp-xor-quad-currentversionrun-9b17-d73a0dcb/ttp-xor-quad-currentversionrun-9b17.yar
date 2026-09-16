rule TTP_XOR_QUAD_CurrentVersionRun_9b17 {
  strings:
    $key_9b17 = { c8 78 [2] ec 76 [2] c7 5a [2] e9 78 [2] fd 63 [2] f2 79 [2] ec 64 [2] ee 65 [2] f5 63 [2] e9 64 [2] f5 4b }

  condition:
    any of them
}