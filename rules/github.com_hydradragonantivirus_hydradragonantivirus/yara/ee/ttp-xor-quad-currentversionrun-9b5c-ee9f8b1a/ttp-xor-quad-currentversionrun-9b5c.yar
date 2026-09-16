rule TTP_XOR_QUAD_CurrentVersionRun_9b5c {
  strings:
    $key_9b5c = { c8 33 [2] ec 3d [2] c7 11 [2] e9 33 [2] fd 28 [2] f2 32 [2] ec 2f [2] ee 2e [2] f5 28 [2] e9 2f [2] f5 00 }

  condition:
    any of them
}