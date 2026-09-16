rule TTP_XOR_QUAD_CurrentVersionRun_9a38 {
  strings:
    $key_9a38 = { c9 57 [2] ed 59 [2] c6 75 [2] e8 57 [2] fc 4c [2] f3 56 [2] ed 4b [2] ef 4a [2] f4 4c [2] e8 4b [2] f4 64 }

  condition:
    any of them
}