rule TTP_XOR_QUAD_CurrentVersionRun_86dc {
  strings:
    $key_86dc = { d5 b3 [2] f1 bd [2] da 91 [2] f4 b3 [2] e0 a8 [2] ef b2 [2] f1 af [2] f3 ae [2] e8 a8 [2] f4 af [2] e8 80 }

  condition:
    any of them
}