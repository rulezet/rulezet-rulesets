rule TTP_XOR_QUAD_CurrentVersionRun_875e {
  strings:
    $key_875e = { d4 31 [2] f0 3f [2] db 13 [2] f5 31 [2] e1 2a [2] ee 30 [2] f0 2d [2] f2 2c [2] e9 2a [2] f5 2d [2] e9 02 }

  condition:
    any of them
}