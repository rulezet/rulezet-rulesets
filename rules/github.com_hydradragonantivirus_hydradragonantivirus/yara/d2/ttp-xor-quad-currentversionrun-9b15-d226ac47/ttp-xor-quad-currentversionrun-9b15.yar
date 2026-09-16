rule TTP_XOR_QUAD_CurrentVersionRun_9b15 {
  strings:
    $key_9b15 = { c8 7a [2] ec 74 [2] c7 58 [2] e9 7a [2] fd 61 [2] f2 7b [2] ec 66 [2] ee 67 [2] f5 61 [2] e9 66 [2] f5 49 }

  condition:
    any of them
}