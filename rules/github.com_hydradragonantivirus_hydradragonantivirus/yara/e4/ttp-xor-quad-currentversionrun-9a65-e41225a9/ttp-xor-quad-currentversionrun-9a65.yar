rule TTP_XOR_QUAD_CurrentVersionRun_9a65 {
  strings:
    $key_9a65 = { c9 0a [2] ed 04 [2] c6 28 [2] e8 0a [2] fc 11 [2] f3 0b [2] ed 16 [2] ef 17 [2] f4 11 [2] e8 16 [2] f4 39 }

  condition:
    any of them
}