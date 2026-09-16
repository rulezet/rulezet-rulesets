rule TTP_XOR_QUAD_CurrentVersionRun_9118 {
  strings:
    $key_9118 = { c2 77 [2] e6 79 [2] cd 55 [2] e3 77 [2] f7 6c [2] f8 76 [2] e6 6b [2] e4 6a [2] ff 6c [2] e3 6b [2] ff 44 }

  condition:
    any of them
}