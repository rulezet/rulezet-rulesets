rule TTP_XOR_QUAD_CurrentVersionRun_9246 {
  strings:
    $key_9246 = { c1 29 [2] e5 27 [2] ce 0b [2] e0 29 [2] f4 32 [2] fb 28 [2] e5 35 [2] e7 34 [2] fc 32 [2] e0 35 [2] fc 1a }

  condition:
    any of them
}