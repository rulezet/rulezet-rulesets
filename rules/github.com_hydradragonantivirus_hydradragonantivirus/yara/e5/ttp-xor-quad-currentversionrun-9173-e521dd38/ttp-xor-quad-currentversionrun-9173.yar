rule TTP_XOR_QUAD_CurrentVersionRun_9173 {
  strings:
    $key_9173 = { c2 1c [2] e6 12 [2] cd 3e [2] e3 1c [2] f7 07 [2] f8 1d [2] e6 00 [2] e4 01 [2] ff 07 [2] e3 00 [2] ff 2f }

  condition:
    any of them
}