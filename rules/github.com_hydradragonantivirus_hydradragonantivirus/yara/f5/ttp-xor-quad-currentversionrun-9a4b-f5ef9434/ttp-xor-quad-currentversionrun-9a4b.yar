rule TTP_XOR_QUAD_CurrentVersionRun_9a4b {
  strings:
    $key_9a4b = { c9 24 [2] ed 2a [2] c6 06 [2] e8 24 [2] fc 3f [2] f3 25 [2] ed 38 [2] ef 39 [2] f4 3f [2] e8 38 [2] f4 17 }

  condition:
    any of them
}