rule TTP_XOR_QUAD_CurrentVersionRun_9175 {
  strings:
    $key_9175 = { c2 1a [2] e6 14 [2] cd 38 [2] e3 1a [2] f7 01 [2] f8 1b [2] e6 06 [2] e4 07 [2] ff 01 [2] e3 06 [2] ff 29 }

  condition:
    any of them
}