rule TTP_XOR_QUAD_CurrentVersionRun_815c {
  strings:
    $key_815c = { d2 33 [2] f6 3d [2] dd 11 [2] f3 33 [2] e7 28 [2] e8 32 [2] f6 2f [2] f4 2e [2] ef 28 [2] f3 2f [2] ef 00 }

  condition:
    any of them
}