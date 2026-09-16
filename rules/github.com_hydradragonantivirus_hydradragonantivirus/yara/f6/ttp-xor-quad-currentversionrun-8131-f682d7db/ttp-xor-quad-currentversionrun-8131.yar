rule TTP_XOR_QUAD_CurrentVersionRun_8131 {
  strings:
    $key_8131 = { d2 5e [2] f6 50 [2] dd 7c [2] f3 5e [2] e7 45 [2] e8 5f [2] f6 42 [2] f4 43 [2] ef 45 [2] f3 42 [2] ef 6d }

  condition:
    any of them
}