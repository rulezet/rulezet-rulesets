rule TTP_XOR_QUAD_CurrentVersionRun_86c2 {
  strings:
    $key_86c2 = { d5 ad [2] f1 a3 [2] da 8f [2] f4 ad [2] e0 b6 [2] ef ac [2] f1 b1 [2] f3 b0 [2] e8 b6 [2] f4 b1 [2] e8 9e }

  condition:
    any of them
}