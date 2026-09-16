rule TTP_XOR_QUAD_CurrentVersionRun_86f0 {
  strings:
    $key_86f0 = { d5 9f [2] f1 91 [2] da bd [2] f4 9f [2] e0 84 [2] ef 9e [2] f1 83 [2] f3 82 [2] e8 84 [2] f4 83 [2] e8 ac }

  condition:
    any of them
}