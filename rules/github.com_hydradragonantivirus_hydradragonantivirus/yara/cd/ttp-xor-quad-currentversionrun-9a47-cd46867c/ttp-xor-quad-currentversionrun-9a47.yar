rule TTP_XOR_QUAD_CurrentVersionRun_9a47 {
  strings:
    $key_9a47 = { c9 28 [2] ed 26 [2] c6 0a [2] e8 28 [2] fc 33 [2] f3 29 [2] ed 34 [2] ef 35 [2] f4 33 [2] e8 34 [2] f4 1b }

  condition:
    any of them
}