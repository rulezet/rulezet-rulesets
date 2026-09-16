rule TTP_XOR_QUAD_CurrentVersionRun_9138 {
  strings:
    $key_9138 = { c2 57 [2] e6 59 [2] cd 75 [2] e3 57 [2] f7 4c [2] f8 56 [2] e6 4b [2] e4 4a [2] ff 4c [2] e3 4b [2] ff 64 }

  condition:
    any of them
}