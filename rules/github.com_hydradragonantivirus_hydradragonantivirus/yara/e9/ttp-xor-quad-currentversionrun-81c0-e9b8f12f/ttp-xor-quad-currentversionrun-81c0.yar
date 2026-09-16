rule TTP_XOR_QUAD_CurrentVersionRun_81c0 {
  strings:
    $key_81c0 = { d2 af [2] f6 a1 [2] dd 8d [2] f3 af [2] e7 b4 [2] e8 ae [2] f6 b3 [2] f4 b2 [2] ef b4 [2] f3 b3 [2] ef 9c }

  condition:
    any of them
}