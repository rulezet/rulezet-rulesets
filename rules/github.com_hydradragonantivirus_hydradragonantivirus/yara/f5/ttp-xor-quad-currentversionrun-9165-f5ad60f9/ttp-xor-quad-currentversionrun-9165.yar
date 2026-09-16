rule TTP_XOR_QUAD_CurrentVersionRun_9165 {
  strings:
    $key_9165 = { c2 0a [2] e6 04 [2] cd 28 [2] e3 0a [2] f7 11 [2] f8 0b [2] e6 16 [2] e4 17 [2] ff 11 [2] e3 16 [2] ff 39 }

  condition:
    any of them
}