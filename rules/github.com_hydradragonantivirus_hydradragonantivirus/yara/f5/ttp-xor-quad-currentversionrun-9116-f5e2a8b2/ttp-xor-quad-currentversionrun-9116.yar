rule TTP_XOR_QUAD_CurrentVersionRun_9116 {
  strings:
    $key_9116 = { c2 79 [2] e6 77 [2] cd 5b [2] e3 79 [2] f7 62 [2] f8 78 [2] e6 65 [2] e4 64 [2] ff 62 [2] e3 65 [2] ff 4a }

  condition:
    any of them
}