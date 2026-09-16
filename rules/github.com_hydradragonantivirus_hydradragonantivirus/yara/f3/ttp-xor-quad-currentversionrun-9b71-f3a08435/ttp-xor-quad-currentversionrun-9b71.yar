rule TTP_XOR_QUAD_CurrentVersionRun_9b71 {
  strings:
    $key_9b71 = { c8 1e [2] ec 10 [2] c7 3c [2] e9 1e [2] fd 05 [2] f2 1f [2] ec 02 [2] ee 03 [2] f5 05 [2] e9 02 [2] f5 2d }

  condition:
    any of them
}