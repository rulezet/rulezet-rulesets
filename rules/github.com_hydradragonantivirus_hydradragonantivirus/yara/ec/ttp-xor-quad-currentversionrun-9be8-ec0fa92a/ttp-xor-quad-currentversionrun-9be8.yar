rule TTP_XOR_QUAD_CurrentVersionRun_9be8 {
  strings:
    $key_9be8 = { c8 87 [2] ec 89 [2] c7 a5 [2] e9 87 [2] fd 9c [2] f2 86 [2] ec 9b [2] ee 9a [2] f5 9c [2] e9 9b [2] f5 b4 }

  condition:
    any of them
}