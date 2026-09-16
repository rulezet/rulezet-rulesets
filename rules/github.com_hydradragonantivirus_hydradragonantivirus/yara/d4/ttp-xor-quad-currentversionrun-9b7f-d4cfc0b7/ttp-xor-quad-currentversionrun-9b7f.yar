rule TTP_XOR_QUAD_CurrentVersionRun_9b7f {
  strings:
    $key_9b7f = { c8 10 [2] ec 1e [2] c7 32 [2] e9 10 [2] fd 0b [2] f2 11 [2] ec 0c [2] ee 0d [2] f5 0b [2] e9 0c [2] f5 23 }

  condition:
    any of them
}