rule TTP_XOR_QUAD_CurrentVersionRun_8638 {
  strings:
    $key_8638 = { d5 57 [2] f1 59 [2] da 75 [2] f4 57 [2] e0 4c [2] ef 56 [2] f1 4b [2] f3 4a [2] e8 4c [2] f4 4b [2] e8 64 }

  condition:
    any of them
}