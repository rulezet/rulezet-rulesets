rule TTP_XOR_QUAD_CurrentVersionRun_8103 {
  strings:
    $key_8103 = { d2 6c [2] f6 62 [2] dd 4e [2] f3 6c [2] e7 77 [2] e8 6d [2] f6 70 [2] f4 71 [2] ef 77 [2] f3 70 [2] ef 5f }

  condition:
    any of them
}