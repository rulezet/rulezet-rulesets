rule TTP_XOR_QUAD_CurrentVersionRun_8110 {
  strings:
    $key_8110 = { d2 7f [2] f6 71 [2] dd 5d [2] f3 7f [2] e7 64 [2] e8 7e [2] f6 63 [2] f4 62 [2] ef 64 [2] f3 63 [2] ef 4c }

  condition:
    any of them
}