rule TTP_XOR_QUAD_CurrentVersionRun_86f7 {
  strings:
    $key_86f7 = { d5 98 [2] f1 96 [2] da ba [2] f4 98 [2] e0 83 [2] ef 99 [2] f1 84 [2] f3 85 [2] e8 83 [2] f4 84 [2] e8 ab }

  condition:
    any of them
}