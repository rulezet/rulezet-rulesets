rule TTP_XOR_QUAD_CurrentVersionRun_9a24 {
  strings:
    $key_9a24 = { c9 4b [2] ed 45 [2] c6 69 [2] e8 4b [2] fc 50 [2] f3 4a [2] ed 57 [2] ef 56 [2] f4 50 [2] e8 57 [2] f4 78 }

  condition:
    any of them
}