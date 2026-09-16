rule TTP_XOR_QUAD_CurrentVersionRun_9a09 {
  strings:
    $key_9a09 = { c9 66 [2] ed 68 [2] c6 44 [2] e8 66 [2] fc 7d [2] f3 67 [2] ed 7a [2] ef 7b [2] f4 7d [2] e8 7a [2] f4 55 }

  condition:
    any of them
}