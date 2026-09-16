rule TTP_XOR_QUAD_CurrentVersionRun_86c0 {
  strings:
    $key_86c0 = { d5 af [2] f1 a1 [2] da 8d [2] f4 af [2] e0 b4 [2] ef ae [2] f1 b3 [2] f3 b2 [2] e8 b4 [2] f4 b3 [2] e8 9c }

  condition:
    any of them
}