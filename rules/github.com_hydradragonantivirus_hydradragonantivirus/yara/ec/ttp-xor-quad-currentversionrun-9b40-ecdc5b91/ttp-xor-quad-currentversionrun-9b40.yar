rule TTP_XOR_QUAD_CurrentVersionRun_9b40 {
  strings:
    $key_9b40 = { c8 2f [2] ec 21 [2] c7 0d [2] e9 2f [2] fd 34 [2] f2 2e [2] ec 33 [2] ee 32 [2] f5 34 [2] e9 33 [2] f5 1c }

  condition:
    any of them
}