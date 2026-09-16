rule TTP_XOR_QUAD_CurrentVersionRun_9224 {
  strings:
    $key_9224 = { c1 4b [2] e5 45 [2] ce 69 [2] e0 4b [2] f4 50 [2] fb 4a [2] e5 57 [2] e7 56 [2] fc 50 [2] e0 57 [2] fc 78 }

  condition:
    any of them
}