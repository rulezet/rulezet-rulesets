rule TTP_XOR_QUAD_CurrentVersionRun_813a {
  strings:
    $key_813a = { d2 55 [2] f6 5b [2] dd 77 [2] f3 55 [2] e7 4e [2] e8 54 [2] f6 49 [2] f4 48 [2] ef 4e [2] f3 49 [2] ef 66 }

  condition:
    any of them
}