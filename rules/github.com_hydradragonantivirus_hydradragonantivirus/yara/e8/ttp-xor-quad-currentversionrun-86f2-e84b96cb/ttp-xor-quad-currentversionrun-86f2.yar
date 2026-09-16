rule TTP_XOR_QUAD_CurrentVersionRun_86f2 {
  strings:
    $key_86f2 = { d5 9d [2] f1 93 [2] da bf [2] f4 9d [2] e0 86 [2] ef 9c [2] f1 81 [2] f3 80 [2] e8 86 [2] f4 81 [2] e8 ae }

  condition:
    any of them
}