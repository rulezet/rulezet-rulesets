rule TTP_XOR_QUAD_CurrentVersionRun_861e {
  strings:
    $key_861e = { d5 71 [2] f1 7f [2] da 53 [2] f4 71 [2] e0 6a [2] ef 70 [2] f1 6d [2] f3 6c [2] e8 6a [2] f4 6d [2] e8 42 }

  condition:
    any of them
}