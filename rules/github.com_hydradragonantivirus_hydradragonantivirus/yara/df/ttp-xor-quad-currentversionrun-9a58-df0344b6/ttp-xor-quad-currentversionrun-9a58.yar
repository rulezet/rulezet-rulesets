rule TTP_XOR_QUAD_CurrentVersionRun_9a58 {
  strings:
    $key_9a58 = { c9 37 [2] ed 39 [2] c6 15 [2] e8 37 [2] fc 2c [2] f3 36 [2] ed 2b [2] ef 2a [2] f4 2c [2] e8 2b [2] f4 04 }

  condition:
    any of them
}