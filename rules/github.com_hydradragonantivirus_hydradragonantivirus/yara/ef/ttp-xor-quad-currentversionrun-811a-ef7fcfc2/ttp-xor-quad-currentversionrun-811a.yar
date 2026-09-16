rule TTP_XOR_QUAD_CurrentVersionRun_811a {
  strings:
    $key_811a = { d2 75 [2] f6 7b [2] dd 57 [2] f3 75 [2] e7 6e [2] e8 74 [2] f6 69 [2] f4 68 [2] ef 6e [2] f3 69 [2] ef 46 }

  condition:
    any of them
}