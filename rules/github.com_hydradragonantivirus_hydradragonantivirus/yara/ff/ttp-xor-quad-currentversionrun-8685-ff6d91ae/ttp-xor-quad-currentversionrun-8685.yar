rule TTP_XOR_QUAD_CurrentVersionRun_8685 {
  strings:
    $key_8685 = { d5 ea [2] f1 e4 [2] da c8 [2] f4 ea [2] e0 f1 [2] ef eb [2] f1 f6 [2] f3 f7 [2] e8 f1 [2] f4 f6 [2] e8 d9 }

  condition:
    any of them
}