rule TTP_XOR_QUAD_CurrentVersionRun_8700 {
  strings:
    $key_8700 = { d4 6f [2] f0 61 [2] db 4d [2] f5 6f [2] e1 74 [2] ee 6e [2] f0 73 [2] f2 72 [2] e9 74 [2] f5 73 [2] e9 5c }

  condition:
    any of them
}