rule TTP_XOR_QUAD_CurrentVersionRun_9b0d {
  strings:
    $key_9b0d = { c8 62 [2] ec 6c [2] c7 40 [2] e9 62 [2] fd 79 [2] f2 63 [2] ec 7e [2] ee 7f [2] f5 79 [2] e9 7e [2] f5 51 }

  condition:
    any of them
}