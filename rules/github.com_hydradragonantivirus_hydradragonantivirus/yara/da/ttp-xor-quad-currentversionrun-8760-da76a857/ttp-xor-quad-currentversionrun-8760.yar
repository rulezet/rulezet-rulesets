rule TTP_XOR_QUAD_CurrentVersionRun_8760 {
  strings:
    $key_8760 = { d4 0f [2] f0 01 [2] db 2d [2] f5 0f [2] e1 14 [2] ee 0e [2] f0 13 [2] f2 12 [2] e9 14 [2] f5 13 [2] e9 3c }

  condition:
    any of them
}