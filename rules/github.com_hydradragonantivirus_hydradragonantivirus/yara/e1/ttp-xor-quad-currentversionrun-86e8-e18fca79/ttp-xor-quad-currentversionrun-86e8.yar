rule TTP_XOR_QUAD_CurrentVersionRun_86e8 {
  strings:
    $key_86e8 = { d5 87 [2] f1 89 [2] da a5 [2] f4 87 [2] e0 9c [2] ef 86 [2] f1 9b [2] f3 9a [2] e8 9c [2] f4 9b [2] e8 b4 }

  condition:
    any of them
}