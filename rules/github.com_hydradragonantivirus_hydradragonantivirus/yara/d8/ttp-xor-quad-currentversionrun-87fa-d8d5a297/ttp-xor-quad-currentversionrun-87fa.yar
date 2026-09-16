rule TTP_XOR_QUAD_CurrentVersionRun_87fa {
  strings:
    $key_87fa = { d4 95 [2] f0 9b [2] db b7 [2] f5 95 [2] e1 8e [2] ee 94 [2] f0 89 [2] f2 88 [2] e9 8e [2] f5 89 [2] e9 a6 }

  condition:
    any of them
}