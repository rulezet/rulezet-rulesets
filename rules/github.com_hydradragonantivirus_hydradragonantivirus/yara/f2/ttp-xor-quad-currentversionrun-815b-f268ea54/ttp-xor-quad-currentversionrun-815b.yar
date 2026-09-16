rule TTP_XOR_QUAD_CurrentVersionRun_815b {
  strings:
    $key_815b = { d2 34 [2] f6 3a [2] dd 16 [2] f3 34 [2] e7 2f [2] e8 35 [2] f6 28 [2] f4 29 [2] ef 2f [2] f3 28 [2] ef 07 }

  condition:
    any of them
}