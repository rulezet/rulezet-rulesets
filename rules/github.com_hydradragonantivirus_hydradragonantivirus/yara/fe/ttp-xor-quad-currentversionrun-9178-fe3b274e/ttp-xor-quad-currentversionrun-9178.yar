rule TTP_XOR_QUAD_CurrentVersionRun_9178 {
  strings:
    $key_9178 = { c2 17 [2] e6 19 [2] cd 35 [2] e3 17 [2] f7 0c [2] f8 16 [2] e6 0b [2] e4 0a [2] ff 0c [2] e3 0b [2] ff 24 }

  condition:
    any of them
}