rule TTP_XOR_QUAD_CurrentVersionRun_8671 {
  strings:
    $key_8671 = { d5 1e [2] f1 10 [2] da 3c [2] f4 1e [2] e0 05 [2] ef 1f [2] f1 02 [2] f3 03 [2] e8 05 [2] f4 02 [2] e8 2d }

  condition:
    any of them
}