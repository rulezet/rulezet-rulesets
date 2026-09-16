rule TTP_XOR_QUAD_CurrentVersionRun_9b1c {
  strings:
    $key_9b1c = { c8 73 [2] ec 7d [2] c7 51 [2] e9 73 [2] fd 68 [2] f2 72 [2] ec 6f [2] ee 6e [2] f5 68 [2] e9 6f [2] f5 40 }

  condition:
    any of them
}