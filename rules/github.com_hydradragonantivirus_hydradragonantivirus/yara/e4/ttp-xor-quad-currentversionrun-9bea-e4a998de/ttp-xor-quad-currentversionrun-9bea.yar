rule TTP_XOR_QUAD_CurrentVersionRun_9bea {
  strings:
    $key_9bea = { c8 85 [2] ec 8b [2] c7 a7 [2] e9 85 [2] fd 9e [2] f2 84 [2] ec 99 [2] ee 98 [2] f5 9e [2] e9 99 [2] f5 b6 }

  condition:
    any of them
}