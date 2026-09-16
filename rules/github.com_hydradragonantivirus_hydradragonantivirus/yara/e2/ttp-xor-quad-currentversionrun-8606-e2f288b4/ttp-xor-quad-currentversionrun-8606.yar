rule TTP_XOR_QUAD_CurrentVersionRun_8606 {
  strings:
    $key_8606 = { d5 69 [2] f1 67 [2] da 4b [2] f4 69 [2] e0 72 [2] ef 68 [2] f1 75 [2] f3 74 [2] e8 72 [2] f4 75 [2] e8 5a }

  condition:
    any of them
}