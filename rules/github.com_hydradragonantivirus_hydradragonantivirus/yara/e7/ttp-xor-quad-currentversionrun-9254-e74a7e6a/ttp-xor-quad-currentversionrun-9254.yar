rule TTP_XOR_QUAD_CurrentVersionRun_9254 {
  strings:
    $key_9254 = { c1 3b [2] e5 35 [2] ce 19 [2] e0 3b [2] f4 20 [2] fb 3a [2] e5 27 [2] e7 26 [2] fc 20 [2] e0 27 [2] fc 08 }

  condition:
    any of them
}