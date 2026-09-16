rule TTP_XOR_QUAD_CurrentVersionRun_9a03 {
  strings:
    $key_9a03 = { c9 6c [2] ed 62 [2] c6 4e [2] e8 6c [2] fc 77 [2] f3 6d [2] ed 70 [2] ef 71 [2] f4 77 [2] e8 70 [2] f4 5f }

  condition:
    any of them
}