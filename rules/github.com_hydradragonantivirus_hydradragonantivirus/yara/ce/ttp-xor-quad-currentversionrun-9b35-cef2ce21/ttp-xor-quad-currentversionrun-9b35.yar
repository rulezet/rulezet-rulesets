rule TTP_XOR_QUAD_CurrentVersionRun_9b35 {
  strings:
    $key_9b35 = { c8 5a [2] ec 54 [2] c7 78 [2] e9 5a [2] fd 41 [2] f2 5b [2] ec 46 [2] ee 47 [2] f5 41 [2] e9 46 [2] f5 69 }

  condition:
    any of them
}