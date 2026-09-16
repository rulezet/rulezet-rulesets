rule TTP_XOR_QUAD_CurrentVersionRun_813e {
  strings:
    $key_813e = { d2 51 [2] f6 5f [2] dd 73 [2] f3 51 [2] e7 4a [2] e8 50 [2] f6 4d [2] f4 4c [2] ef 4a [2] f3 4d [2] ef 62 }

  condition:
    any of them
}