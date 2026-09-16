rule TTP_XOR_QUAD_CurrentVersionRun_812d {
  strings:
    $key_812d = { d2 42 [2] f6 4c [2] dd 60 [2] f3 42 [2] e7 59 [2] e8 43 [2] f6 5e [2] f4 5f [2] ef 59 [2] f3 5e [2] ef 71 }

  condition:
    any of them
}