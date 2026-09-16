rule TTP_XOR_QUAD_CurrentVersionRun_9177 {
  strings:
    $key_9177 = { c2 18 [2] e6 16 [2] cd 3a [2] e3 18 [2] f7 03 [2] f8 19 [2] e6 04 [2] e4 05 [2] ff 03 [2] e3 04 [2] ff 2b }

  condition:
    any of them
}