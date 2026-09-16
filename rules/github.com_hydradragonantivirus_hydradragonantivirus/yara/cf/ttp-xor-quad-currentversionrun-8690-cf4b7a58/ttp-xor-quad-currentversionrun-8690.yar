rule TTP_XOR_QUAD_CurrentVersionRun_8690 {
  strings:
    $key_8690 = { d5 ff [2] f1 f1 [2] da dd [2] f4 ff [2] e0 e4 [2] ef fe [2] f1 e3 [2] f3 e2 [2] e8 e4 [2] f4 e3 [2] e8 cc }

  condition:
    any of them
}