rule TTP_XOR_QUAD_CurrentVersionRun_9b31 {
  strings:
    $key_9b31 = { c8 5e [2] ec 50 [2] c7 7c [2] e9 5e [2] fd 45 [2] f2 5f [2] ec 42 [2] ee 43 [2] f5 45 [2] e9 42 [2] f5 6d }

  condition:
    any of them
}