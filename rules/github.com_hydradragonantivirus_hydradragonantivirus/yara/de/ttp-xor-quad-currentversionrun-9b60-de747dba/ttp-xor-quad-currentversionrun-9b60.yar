rule TTP_XOR_QUAD_CurrentVersionRun_9b60 {
  strings:
    $key_9b60 = { c8 0f [2] ec 01 [2] c7 2d [2] e9 0f [2] fd 14 [2] f2 0e [2] ec 13 [2] ee 12 [2] f5 14 [2] e9 13 [2] f5 3c }

  condition:
    any of them
}