rule TTP_XOR_QUAD_CurrentVersionRun_8684 {
  strings:
    $key_8684 = { d5 eb [2] f1 e5 [2] da c9 [2] f4 eb [2] e0 f0 [2] ef ea [2] f1 f7 [2] f3 f6 [2] e8 f0 [2] f4 f7 [2] e8 d8 }

  condition:
    any of them
}