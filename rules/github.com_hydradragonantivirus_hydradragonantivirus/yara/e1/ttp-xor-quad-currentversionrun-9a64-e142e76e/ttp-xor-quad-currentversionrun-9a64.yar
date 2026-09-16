rule TTP_XOR_QUAD_CurrentVersionRun_9a64 {
  strings:
    $key_9a64 = { c9 0b [2] ed 05 [2] c6 29 [2] e8 0b [2] fc 10 [2] f3 0a [2] ed 17 [2] ef 16 [2] f4 10 [2] e8 17 [2] f4 38 }

  condition:
    any of them
}