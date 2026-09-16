rule TTP_XOR_QUAD_CurrentVersionRun_9115 {
  strings:
    $key_9115 = { c2 7a [2] e6 74 [2] cd 58 [2] e3 7a [2] f7 61 [2] f8 7b [2] e6 66 [2] e4 67 [2] ff 61 [2] e3 66 [2] ff 49 }

  condition:
    any of them
}