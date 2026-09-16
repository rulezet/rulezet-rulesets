rule TTP_XOR_QUAD_CurrentVersionRun_9a18 {
  strings:
    $key_9a18 = { c9 77 [2] ed 79 [2] c6 55 [2] e8 77 [2] fc 6c [2] f3 76 [2] ed 6b [2] ef 6a [2] f4 6c [2] e8 6b [2] f4 44 }

  condition:
    any of them
}