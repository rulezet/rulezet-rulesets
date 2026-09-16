rule TTP_XOR_QUAD_CurrentVersionRun_9a33 {
  strings:
    $key_9a33 = { c9 5c [2] ed 52 [2] c6 7e [2] e8 5c [2] fc 47 [2] f3 5d [2] ed 40 [2] ef 41 [2] f4 47 [2] e8 40 [2] f4 6f }

  condition:
    any of them
}