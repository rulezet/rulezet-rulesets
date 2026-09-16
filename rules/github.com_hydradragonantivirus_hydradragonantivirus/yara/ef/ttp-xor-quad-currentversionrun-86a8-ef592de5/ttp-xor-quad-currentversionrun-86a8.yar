rule TTP_XOR_QUAD_CurrentVersionRun_86a8 {
  strings:
    $key_86a8 = { d5 c7 [2] f1 c9 [2] da e5 [2] f4 c7 [2] e0 dc [2] ef c6 [2] f1 db [2] f3 da [2] e8 dc [2] f4 db [2] e8 f4 }

  condition:
    any of them
}