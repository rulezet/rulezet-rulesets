rule TTP_XOR_QUAD_CurrentVersionRun_861c {
  strings:
    $key_861c = { d5 73 [2] f1 7d [2] da 51 [2] f4 73 [2] e0 68 [2] ef 72 [2] f1 6f [2] f3 6e [2] e8 68 [2] f4 6f [2] e8 40 }

  condition:
    any of them
}