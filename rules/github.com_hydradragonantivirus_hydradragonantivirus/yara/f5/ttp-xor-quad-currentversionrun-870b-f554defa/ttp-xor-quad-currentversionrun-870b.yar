rule TTP_XOR_QUAD_CurrentVersionRun_870b {
  strings:
    $key_870b = { d4 64 [2] f0 6a [2] db 46 [2] f5 64 [2] e1 7f [2] ee 65 [2] f0 78 [2] f2 79 [2] e9 7f [2] f5 78 [2] e9 57 }

  condition:
    any of them
}