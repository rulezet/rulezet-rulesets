rule TTP_XOR_QUAD_CurrentVersionRun_8141 {
  strings:
    $key_8141 = { d2 2e [2] f6 20 [2] dd 0c [2] f3 2e [2] e7 35 [2] e8 2f [2] f6 32 [2] f4 33 [2] ef 35 [2] f3 32 [2] ef 1d }

  condition:
    any of them
}