rule TTP_XOR_QUAD_CurrentVersionRun_816a {
  strings:
    $key_816a = { d2 05 [2] f6 0b [2] dd 27 [2] f3 05 [2] e7 1e [2] e8 04 [2] f6 19 [2] f4 18 [2] ef 1e [2] f3 19 [2] ef 36 }

  condition:
    any of them
}