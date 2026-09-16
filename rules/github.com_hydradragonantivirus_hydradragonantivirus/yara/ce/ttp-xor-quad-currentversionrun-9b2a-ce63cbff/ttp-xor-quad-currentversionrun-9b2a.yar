rule TTP_XOR_QUAD_CurrentVersionRun_9b2a {
  strings:
    $key_9b2a = { c8 45 [2] ec 4b [2] c7 67 [2] e9 45 [2] fd 5e [2] f2 44 [2] ec 59 [2] ee 58 [2] f5 5e [2] e9 59 [2] f5 76 }

  condition:
    any of them
}