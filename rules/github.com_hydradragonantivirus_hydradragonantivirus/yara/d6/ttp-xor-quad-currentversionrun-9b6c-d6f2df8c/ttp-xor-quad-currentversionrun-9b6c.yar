rule TTP_XOR_QUAD_CurrentVersionRun_9b6c {
  strings:
    $key_9b6c = { c8 03 [2] ec 0d [2] c7 21 [2] e9 03 [2] fd 18 [2] f2 02 [2] ec 1f [2] ee 1e [2] f5 18 [2] e9 1f [2] f5 30 }

  condition:
    any of them
}