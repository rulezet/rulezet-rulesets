rule TTP_XOR_QUAD_CurrentVersionRun_8722 {
  strings:
    $key_8722 = { d4 4d [2] f0 43 [2] db 6f [2] f5 4d [2] e1 56 [2] ee 4c [2] f0 51 [2] f2 50 [2] e9 56 [2] f5 51 [2] e9 7e }

  condition:
    any of them
}