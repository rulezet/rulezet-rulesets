rule TTP_XOR_QUAD_CurrentVersionRun_9128 {
  strings:
    $key_9128 = { c2 47 [2] e6 49 [2] cd 65 [2] e3 47 [2] f7 5c [2] f8 46 [2] e6 5b [2] e4 5a [2] ff 5c [2] e3 5b [2] ff 74 }

  condition:
    any of them
}