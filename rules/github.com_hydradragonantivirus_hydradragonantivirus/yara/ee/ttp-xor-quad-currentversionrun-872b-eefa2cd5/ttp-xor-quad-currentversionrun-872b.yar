rule TTP_XOR_QUAD_CurrentVersionRun_872b {
  strings:
    $key_872b = { d4 44 [2] f0 4a [2] db 66 [2] f5 44 [2] e1 5f [2] ee 45 [2] f0 58 [2] f2 59 [2] e9 5f [2] f5 58 [2] e9 77 }

  condition:
    any of them
}