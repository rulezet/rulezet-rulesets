rule TTP_XOR_QUAD_CurrentVersionRun_87ef {
  strings:
    $key_87ef = { d4 80 [2] f0 8e [2] db a2 [2] f5 80 [2] e1 9b [2] ee 81 [2] f0 9c [2] f2 9d [2] e9 9b [2] f5 9c [2] e9 b3 }

  condition:
    any of them
}