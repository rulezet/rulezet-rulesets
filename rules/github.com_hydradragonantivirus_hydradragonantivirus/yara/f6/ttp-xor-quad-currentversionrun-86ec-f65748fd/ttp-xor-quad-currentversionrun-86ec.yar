rule TTP_XOR_QUAD_CurrentVersionRun_86ec {
  strings:
    $key_86ec = { d5 83 [2] f1 8d [2] da a1 [2] f4 83 [2] e0 98 [2] ef 82 [2] f1 9f [2] f3 9e [2] e8 98 [2] f4 9f [2] e8 b0 }

  condition:
    any of them
}