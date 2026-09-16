rule TTP_XOR_QUAD_CurrentVersionRun_81f0 {
  strings:
    $key_81f0 = { d2 9f [2] f6 91 [2] dd bd [2] f3 9f [2] e7 84 [2] e8 9e [2] f6 83 [2] f4 82 [2] ef 84 [2] f3 83 [2] ef ac }

  condition:
    any of them
}