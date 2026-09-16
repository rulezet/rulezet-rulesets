rule TTP_XOR_QUAD_CurrentVersionRun_8660 {
  strings:
    $key_8660 = { d5 0f [2] f1 01 [2] da 2d [2] f4 0f [2] e0 14 [2] ef 0e [2] f1 13 [2] f3 12 [2] e8 14 [2] f4 13 [2] e8 3c }

  condition:
    any of them
}