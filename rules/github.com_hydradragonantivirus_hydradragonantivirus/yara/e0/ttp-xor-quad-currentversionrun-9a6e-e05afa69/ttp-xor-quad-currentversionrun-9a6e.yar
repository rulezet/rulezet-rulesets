rule TTP_XOR_QUAD_CurrentVersionRun_9a6e {
  strings:
    $key_9a6e = { c9 01 [2] ed 0f [2] c6 23 [2] e8 01 [2] fc 1a [2] f3 00 [2] ed 1d [2] ef 1c [2] f4 1a [2] e8 1d [2] f4 32 }

  condition:
    any of them
}