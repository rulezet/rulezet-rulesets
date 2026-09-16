rule TTP_XOR_QUAD_CurrentVersionRun_9bec {
  strings:
    $key_9bec = { c8 83 [2] ec 8d [2] c7 a1 [2] e9 83 [2] fd 98 [2] f2 82 [2] ec 9f [2] ee 9e [2] f5 98 [2] e9 9f [2] f5 b0 }

  condition:
    any of them
}