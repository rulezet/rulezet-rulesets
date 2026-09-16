rule TTP_XOR_QUAD_CurrentVersionRun_9a0e {
  strings:
    $key_9a0e = { c9 61 [2] ed 6f [2] c6 43 [2] e8 61 [2] fc 7a [2] f3 60 [2] ed 7d [2] ef 7c [2] f4 7a [2] e8 7d [2] f4 52 }

  condition:
    any of them
}