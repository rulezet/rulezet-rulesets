rule TTP_XOR_QUAD_CurrentVersionRun_9256 {
  strings:
    $key_9256 = { c1 39 [2] e5 37 [2] ce 1b [2] e0 39 [2] f4 22 [2] fb 38 [2] e5 25 [2] e7 24 [2] fc 22 [2] e0 25 [2] fc 0a }

  condition:
    any of them
}