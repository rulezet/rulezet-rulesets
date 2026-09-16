rule TTP_XOR_QUAD_CurrentVersionRun_9b24 {
  strings:
    $key_9b24 = { c8 4b [2] ec 45 [2] c7 69 [2] e9 4b [2] fd 50 [2] f2 4a [2] ec 57 [2] ee 56 [2] f5 50 [2] e9 57 [2] f5 78 }

  condition:
    any of them
}