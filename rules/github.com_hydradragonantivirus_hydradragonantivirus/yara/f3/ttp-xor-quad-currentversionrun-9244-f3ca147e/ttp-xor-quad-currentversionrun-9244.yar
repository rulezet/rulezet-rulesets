rule TTP_XOR_QUAD_CurrentVersionRun_9244 {
  strings:
    $key_9244 = { c1 2b [2] e5 25 [2] ce 09 [2] e0 2b [2] f4 30 [2] fb 2a [2] e5 37 [2] e7 36 [2] fc 30 [2] e0 37 [2] fc 18 }

  condition:
    any of them
}