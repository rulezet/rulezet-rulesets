rule TTP_XOR_QUAD_CurrentVersionRun_9148 {
  strings:
    $key_9148 = { c2 27 [2] e6 29 [2] cd 05 [2] e3 27 [2] f7 3c [2] f8 26 [2] e6 3b [2] e4 3a [2] ff 3c [2] e3 3b [2] ff 14 }

  condition:
    any of them
}