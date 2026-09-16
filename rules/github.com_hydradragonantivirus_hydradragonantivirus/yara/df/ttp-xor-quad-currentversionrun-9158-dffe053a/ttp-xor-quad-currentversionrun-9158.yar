rule TTP_XOR_QUAD_CurrentVersionRun_9158 {
  strings:
    $key_9158 = { c2 37 [2] e6 39 [2] cd 15 [2] e3 37 [2] f7 2c [2] f8 36 [2] e6 2b [2] e4 2a [2] ff 2c [2] e3 2b [2] ff 04 }

  condition:
    any of them
}