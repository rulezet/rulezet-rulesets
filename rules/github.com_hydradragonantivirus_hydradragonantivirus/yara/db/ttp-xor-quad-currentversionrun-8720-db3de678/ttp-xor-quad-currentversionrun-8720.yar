rule TTP_XOR_QUAD_CurrentVersionRun_8720 {
  strings:
    $key_8720 = { d4 4f [2] f0 41 [2] db 6d [2] f5 4f [2] e1 54 [2] ee 4e [2] f0 53 [2] f2 52 [2] e9 54 [2] f5 53 [2] e9 7c }

  condition:
    any of them
}