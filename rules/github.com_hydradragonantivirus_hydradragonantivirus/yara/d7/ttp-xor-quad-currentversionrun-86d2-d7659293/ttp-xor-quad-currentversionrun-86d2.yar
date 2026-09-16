rule TTP_XOR_QUAD_CurrentVersionRun_86d2 {
  strings:
    $key_86d2 = { d5 bd [2] f1 b3 [2] da 9f [2] f4 bd [2] e0 a6 [2] ef bc [2] f1 a1 [2] f3 a0 [2] e8 a6 [2] f4 a1 [2] e8 8e }

  condition:
    any of them
}