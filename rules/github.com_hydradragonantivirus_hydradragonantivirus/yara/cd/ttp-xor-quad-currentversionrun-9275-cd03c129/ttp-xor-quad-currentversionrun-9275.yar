rule TTP_XOR_QUAD_CurrentVersionRun_9275 {
  strings:
    $key_9275 = { c1 1a [2] e5 14 [2] ce 38 [2] e0 1a [2] f4 01 [2] fb 1b [2] e5 06 [2] e7 07 [2] fc 01 [2] e0 06 [2] fc 29 }

  condition:
    any of them
}