rule TTP_XOR_QUAD_CurrentVersionRun_81db {
  strings:
    $key_81db = { d2 b4 [2] f6 ba [2] dd 96 [2] f3 b4 [2] e7 af [2] e8 b5 [2] f6 a8 [2] f4 a9 [2] ef af [2] f3 a8 [2] ef 87 }

  condition:
    any of them
}