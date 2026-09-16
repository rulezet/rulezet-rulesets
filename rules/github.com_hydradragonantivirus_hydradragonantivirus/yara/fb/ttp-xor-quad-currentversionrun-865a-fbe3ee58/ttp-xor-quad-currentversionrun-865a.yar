rule TTP_XOR_QUAD_CurrentVersionRun_865a {
  strings:
    $key_865a = { d5 35 [2] f1 3b [2] da 17 [2] f4 35 [2] e0 2e [2] ef 34 [2] f1 29 [2] f3 28 [2] e8 2e [2] f4 29 [2] e8 06 }

  condition:
    any of them
}