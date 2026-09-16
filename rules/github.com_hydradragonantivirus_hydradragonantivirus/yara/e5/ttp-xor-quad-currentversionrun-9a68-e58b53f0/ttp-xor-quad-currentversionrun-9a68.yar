rule TTP_XOR_QUAD_CurrentVersionRun_9a68 {
  strings:
    $key_9a68 = { c9 07 [2] ed 09 [2] c6 25 [2] e8 07 [2] fc 1c [2] f3 06 [2] ed 1b [2] ef 1a [2] f4 1c [2] e8 1b [2] f4 34 }

  condition:
    any of them
}