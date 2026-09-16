rule TTP_XOR_QUAD_CurrentVersionRun_86eb {
  strings:
    $key_86eb = { d5 84 [2] f1 8a [2] da a6 [2] f4 84 [2] e0 9f [2] ef 85 [2] f1 98 [2] f3 99 [2] e8 9f [2] f4 98 [2] e8 b7 }

  condition:
    any of them
}