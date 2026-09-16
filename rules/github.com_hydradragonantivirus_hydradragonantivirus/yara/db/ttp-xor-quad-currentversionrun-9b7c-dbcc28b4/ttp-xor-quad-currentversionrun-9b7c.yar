rule TTP_XOR_QUAD_CurrentVersionRun_9b7c {
  strings:
    $key_9b7c = { c8 13 [2] ec 1d [2] c7 31 [2] e9 13 [2] fd 08 [2] f2 12 [2] ec 0f [2] ee 0e [2] f5 08 [2] e9 0f [2] f5 20 }

  condition:
    any of them
}