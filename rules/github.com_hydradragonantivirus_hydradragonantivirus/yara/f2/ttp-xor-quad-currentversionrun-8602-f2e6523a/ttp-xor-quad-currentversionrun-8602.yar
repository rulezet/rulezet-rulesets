rule TTP_XOR_QUAD_CurrentVersionRun_8602 {
  strings:
    $key_8602 = { d5 6d [2] f1 63 [2] da 4f [2] f4 6d [2] e0 76 [2] ef 6c [2] f1 71 [2] f3 70 [2] e8 76 [2] f4 71 [2] e8 5e }

  condition:
    any of them
}