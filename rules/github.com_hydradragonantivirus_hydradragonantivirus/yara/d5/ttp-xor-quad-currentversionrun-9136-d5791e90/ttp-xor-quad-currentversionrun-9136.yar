rule TTP_XOR_QUAD_CurrentVersionRun_9136 {
  strings:
    $key_9136 = { c2 59 [2] e6 57 [2] cd 7b [2] e3 59 [2] f7 42 [2] f8 58 [2] e6 45 [2] e4 44 [2] ff 42 [2] e3 45 [2] ff 6a }

  condition:
    any of them
}