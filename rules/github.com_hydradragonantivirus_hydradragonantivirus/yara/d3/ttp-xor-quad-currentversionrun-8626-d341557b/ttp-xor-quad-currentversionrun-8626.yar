rule TTP_XOR_QUAD_CurrentVersionRun_8626 {
  strings:
    $key_8626 = { d5 49 [2] f1 47 [2] da 6b [2] f4 49 [2] e0 52 [2] ef 48 [2] f1 55 [2] f3 54 [2] e8 52 [2] f4 55 [2] e8 7a }

  condition:
    any of them
}