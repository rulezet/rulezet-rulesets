rule TTP_XOR_QUAD_CurrentVersionRun_817e {
  strings:
    $key_817e = { d2 11 [2] f6 1f [2] dd 33 [2] f3 11 [2] e7 0a [2] e8 10 [2] f6 0d [2] f4 0c [2] ef 0a [2] f3 0d [2] ef 22 }

  condition:
    any of them
}