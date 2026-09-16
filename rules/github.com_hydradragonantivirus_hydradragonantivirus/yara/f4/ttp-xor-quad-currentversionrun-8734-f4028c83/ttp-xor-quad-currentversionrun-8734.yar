rule TTP_XOR_QUAD_CurrentVersionRun_8734 {
  strings:
    $key_8734 = { d4 5b [2] f0 55 [2] db 79 [2] f5 5b [2] e1 40 [2] ee 5a [2] f0 47 [2] f2 46 [2] e9 40 [2] f5 47 [2] e9 68 }

  condition:
    any of them
}