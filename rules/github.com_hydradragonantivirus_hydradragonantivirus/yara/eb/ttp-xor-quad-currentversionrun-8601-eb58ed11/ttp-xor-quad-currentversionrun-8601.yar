rule TTP_XOR_QUAD_CurrentVersionRun_8601 {
  strings:
    $key_8601 = { d5 6e [2] f1 60 [2] da 4c [2] f4 6e [2] e0 75 [2] ef 6f [2] f1 72 [2] f3 73 [2] e8 75 [2] f4 72 [2] e8 5d }

  condition:
    any of them
}