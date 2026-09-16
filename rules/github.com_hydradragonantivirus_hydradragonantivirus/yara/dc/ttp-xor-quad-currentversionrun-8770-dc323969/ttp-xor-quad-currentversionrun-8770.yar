rule TTP_XOR_QUAD_CurrentVersionRun_8770 {
  strings:
    $key_8770 = { d4 1f [2] f0 11 [2] db 3d [2] f5 1f [2] e1 04 [2] ee 1e [2] f0 03 [2] f2 02 [2] e9 04 [2] f5 03 [2] e9 2c }

  condition:
    any of them
}